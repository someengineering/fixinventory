# resoto-plugin-random
Random Cloud Collector for Resoto

Creates a plausible pseudo-random cloud based on a configurable seed.

The base infrastructure stays the same, but the number of instances vary slightly from run to run so that metrics show some more interesting up/down lines.

The config value `random.seed` is the seed Python's random number generator is seeded with.
`random.size` is a float multiplier that's applied to every random min/max value causing exponential growth of the cloud. E.g. a value of 2 would create on average twice the number of accounts containing twice the number of networks containing twice the number of instances, with twice the number of volumes each.

Given the same seed and size the cloud stays relatively the same plus/minus a couple of instances and their volumes (the jitter). If either seed or size is changed the entire cloud changes.
