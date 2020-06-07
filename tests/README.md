In `generator`, there is a binary that generates > 100 points as well as BLS
signatures with random messages of random lenghts + common cases. The output is
written in the current directory.  In `consumer`, there is a binary that
consumes the output of the former binary and verify results are consistents with
each other.
