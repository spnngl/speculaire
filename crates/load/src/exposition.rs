//! What the load reads of the reflector's `/metrics`: gauges from the text format, and native histograms from the
//! protobuf format (D34), whose quantiles the text format does not carry.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use prost::Message as _;

/// The `Accept` header that asks the exporter for the protobuf exposition.
pub(crate) const PROTOBUF: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// The value of the gauge `name`, without labels, in a text exposition.
pub(crate) fn gauge(text: &str, name: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        line.strip_prefix(name)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

/// A native histogram's counts: its samples and buckets at one scrape (Prometheus' `metrics.proto`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Buckets {
    /// Every bucket's upper bound is `2^(key × 2^-schema)`.
    schema: i32,
    /// Samples at or under the zero threshold, which the exporter keeps under a microsecond.
    zero: u64,
    /// The count of each positive bucket, by key.
    positive: BTreeMap<i32, u64>,
}

impl Buckets {
    /// The histogram without labels named `name` in a protobuf exposition; empty when it has no sample yet.
    pub(crate) fn parse(mut exposition: &[u8], name: &str) -> anyhow::Result<Self> {
        while !exposition.is_empty() {
            let family = Family::decode_length_delimited(&mut exposition)
                .context("the protobuf exposition does not parse")?;
            if family.name != name {
                continue;
            }
            let Some(histogram) = family.metric.into_iter().find_map(|m| m.histogram) else {
                break;
            };
            return Self::from_histogram(histogram);
        }
        Ok(Self::default())
    }

    fn from_histogram(histogram: Histogram) -> anyhow::Result<Self> {
        let mut positive = BTreeMap::new();
        let mut deltas = histogram.positive_delta.into_iter();
        let mut key = 0_i32;
        let mut count = 0_i64;
        for span in histogram.positive_span {
            key = key
                .checked_add(span.offset)
                .context("a bucket key overflows")?;
            for _ in 0..span.length {
                count += deltas.next().context("a span is longer than its deltas")?;
                ensure!(count >= 0, "a bucket count is negative");
                positive.insert(key, count.unsigned_abs());
                key = key.checked_add(1).context("a bucket key overflows")?;
            }
            // The next span's offset counts from the bucket after this one's last.
        }
        let buckets = Self {
            schema: histogram.schema,
            zero: histogram.zero_count,
            positive,
        };
        ensure!(
            buckets.count() == histogram.sample_count,
            "the buckets hold {} samples, the histogram {}: not a native histogram",
            buckets.count(),
            histogram.sample_count
        );
        Ok(buckets)
    }

    /// The samples recorded between `self` and the later `after`, at the coarser schema of the two.
    pub(crate) fn since(&self, after: &Self) -> anyhow::Result<Self> {
        let schema = self.schema.min(after.schema);
        let (before, after) = (self.at(schema)?, after.at(schema)?);
        let mut positive = BTreeMap::new();
        for (key, count) in after.positive {
            let earlier = before.positive.get(&key).copied().unwrap_or(0);
            let new = count
                .checked_sub(earlier)
                .context("a bucket count went down: the reflector restarted between the scrapes")?;
            if new > 0 {
                positive.insert(key, new);
            }
        }
        Ok(Self {
            schema,
            zero: after.zero.checked_sub(before.zero).context(
                "the zero bucket went down: the reflector restarted between the scrapes",
            )?,
            positive,
        })
    }

    /// The same counts in buckets of `schema`, no finer than this one's: a bucket `k` goes to `⌈k / 2^shift⌉`.
    fn at(&self, schema: i32) -> anyhow::Result<Self> {
        let shift = self.schema - schema;
        ensure!(
            (0..31).contains(&shift),
            "cannot rescale schema {} to {schema}",
            self.schema
        );
        let mut positive = BTreeMap::new();
        for (&key, &count) in &self.positive {
            let coarse = (i64::from(key) + (1 << shift) - 1) >> shift;
            *positive
                .entry(i32::try_from(coarse).context("a bucket key overflows")?)
                .or_default() += count;
        }
        Ok(Self {
            schema,
            zero: self.zero,
            positive,
        })
    }

    /// How many samples.
    pub(crate) fn count(&self) -> u64 {
        self.zero + self.positive.values().sum::<u64>()
    }

    /// The upper bound of the bucket that holds the `q` quantile, in seconds: a value the quantile does not exceed.
    /// `None` without samples.
    pub(crate) fn quantile(&self, q: f64) -> Option<Duration> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        // The rank of the quantile's sample, from 1; float to integer by `ceil` on purpose, below 2^53.
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "sample counts stay far below 2^53, and q is in [0, 1]"
        )]
        let rank = ((q * total as f64).ceil() as u64).max(1);
        if rank <= self.zero {
            return Some(Duration::ZERO);
        }
        let mut seen = self.zero;
        for (&key, &count) in &self.positive {
            seen += count;
            if seen >= rank {
                let exponent = f64::from(key) * (-f64::from(self.schema)).exp2();
                return Some(Duration::from_secs_f64(exponent.exp2()));
            }
        }
        None
    }
}

/// What the load reads of a `MetricFamily`.
#[derive(Clone, PartialEq, prost::Message)]
struct Family {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "4")]
    metric: Vec<Series>,
}

/// A `Metric`: only its histogram.
#[derive(Clone, PartialEq, prost::Message)]
struct Series {
    #[prost(message, optional, tag = "7")]
    histogram: Option<Histogram>,
}

/// A native `Histogram`'s count, schema, zero bucket and positive buckets; the reflector records no negative duration.
#[derive(Clone, PartialEq, prost::Message)]
struct Histogram {
    #[prost(uint64, tag = "1")]
    sample_count: u64,
    #[prost(sint32, tag = "5")]
    schema: i32,
    #[prost(uint64, tag = "7")]
    zero_count: u64,
    #[prost(message, repeated, tag = "12")]
    positive_span: Vec<Span>,
    #[prost(sint64, repeated, tag = "13")]
    positive_delta: Vec<i64>,
}

/// A `BucketSpan`: `length` buckets in a row, `offset` keys after the previous span, or after 0 for the first.
#[derive(Clone, PartialEq, prost::Message)]
struct Span {
    #[prost(sint32, tag = "1")]
    offset: i32,
    #[prost(uint32, tag = "2")]
    length: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exposition(name: &str, histogram: Histogram) -> Vec<u8> {
        let mut bytes = Vec::new();
        Family {
            name: "other".into(),
            metric: vec![Series { histogram: None }],
        }
        .encode_length_delimited(&mut bytes)
        .unwrap();
        Family {
            name: name.into(),
            metric: vec![Series {
                histogram: Some(histogram),
            }],
        }
        .encode_length_delimited(&mut bytes)
        .unwrap();
        bytes
    }

    fn buckets(schema: i32, zero: u64, positive: &[(i32, u64)]) -> Buckets {
        Buckets {
            schema,
            zero,
            positive: positive.iter().copied().collect(),
        }
    }

    #[test]
    fn gauges_are_read_by_exact_name() {
        let text = "# HELP a_total x\na_total_more 9\na_total 20000000\nb{x=\"y\"} 3\n";
        assert_eq!(gauge(text, "a_total"), Some(20_000_000.0));
        assert_eq!(gauge(text, "b"), None);
        assert_eq!(gauge(text, "c"), None);
    }

    #[test]
    fn spans_and_deltas_become_bucket_counts() {
        let bytes = exposition(
            "h",
            Histogram {
                sample_count: 15,
                schema: 3,
                zero_count: 2,
                // Keys -5 and -4, then 0: the second span's offset counts from -3.
                positive_span: vec![
                    Span {
                        offset: -5,
                        length: 2,
                    },
                    Span {
                        offset: 3,
                        length: 1,
                    },
                ],
                positive_delta: vec![4, -1, 3],
            },
        );
        assert_eq!(
            Buckets::parse(&bytes, "h").unwrap(),
            buckets(3, 2, &[(-5, 4), (-4, 3), (0, 6)])
        );
        assert_eq!(
            Buckets::parse(&bytes, "absent").unwrap(),
            Buckets::default()
        );
        assert!(Buckets::parse(&[0xff], "h").is_err());
    }

    #[test]
    fn a_classic_histogram_is_refused() {
        let classic = Histogram {
            sample_count: 3,
            ..Histogram::default()
        };
        assert!(Buckets::parse(&exposition("h", classic), "h").is_err());
    }

    #[test]
    fn deltas_shorter_than_spans_or_negative_counts_are_refused() {
        let short = Histogram {
            positive_span: vec![Span {
                offset: 0,
                length: 2,
            }],
            positive_delta: vec![1],
            ..Histogram::default()
        };
        assert!(Buckets::parse(&exposition("h", short), "h").is_err());
        let negative = Histogram {
            positive_span: vec![Span {
                offset: 0,
                length: 1,
            }],
            positive_delta: vec![-1],
            ..Histogram::default()
        };
        assert!(Buckets::parse(&exposition("h", negative), "h").is_err());
    }

    #[test]
    fn a_later_scrape_less_an_earlier_one_is_what_came_between() {
        let before = buckets(3, 1, &[(1, 5), (2, 1)]);
        let after = buckets(3, 3, &[(1, 5), (2, 4), (7, 2)]);
        assert_eq!(
            before.since(&after).unwrap(),
            buckets(3, 2, &[(2, 3), (7, 2)])
        );
        assert!(after.since(&before).is_err());
        assert!(buckets(3, 3, &[]).since(&buckets(3, 1, &[])).is_err());
    }

    #[test]
    fn a_coarser_later_schema_merges_buckets_by_their_ceiling() {
        // At schema 3, keys -3 and -2 are in key -1 of schema 2, and keys 1 and 2 in key 1.
        let before = buckets(3, 0, &[(-3, 1), (-2, 1), (1, 1), (2, 1)]);
        let after = buckets(2, 0, &[(-1, 3), (1, 2), (2, 1)]);
        assert_eq!(
            before.since(&after).unwrap(),
            buckets(2, 0, &[(-1, 1), (2, 1)])
        );
        assert!(buckets(40, 0, &[]).since(&buckets(3, 0, &[])).is_err());
    }

    #[test]
    fn the_quantile_is_its_bucket_upper_bound() {
        assert_eq!(Buckets::default().quantile(0.99), None);
        // Schema 0: key k's bucket ends at 2^k seconds.
        let latencies = buckets(0, 1, &[(-10, 97), (-9, 1), (-3, 1)]);
        assert_eq!(latencies.count(), 100);
        assert_eq!(latencies.quantile(0.01), Some(Duration::ZERO));
        assert_eq!(
            latencies.quantile(0.5),
            Some(Duration::from_secs_f64(2f64.powi(-10)))
        );
        assert_eq!(
            latencies.quantile(0.99),
            Some(Duration::from_secs_f64(2f64.powi(-9)))
        );
        assert_eq!(latencies.quantile(1.0), Some(Duration::from_millis(125)));
        // Schema 1: key 3 ends at 2^1.5 seconds.
        let fine = buckets(1, 0, &[(3, 1)]);
        assert_eq!(
            fine.quantile(0.99),
            Some(Duration::from_secs_f64(2f64.powf(1.5)))
        );
    }
}
