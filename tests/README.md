Test vectors are copied from [zkcrypto/bls12_381](https://github.com/zkcrypto/bls12_381) @  _afe30519f862abfba3ab26ae1ed406dd779db22e_

In `generator`, there is a binary that generates > 100 points as well as BLS signatures with random messages of random lenghts + common cases. The output is written in the current directory.
In `consumer`, there is a binary that consumes the output of the former binary and verify results are consistents with each other.
