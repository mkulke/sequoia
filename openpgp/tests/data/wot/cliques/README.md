Creates 4 10 element cliques.  To authenticate the target, the path
finder must find it's way through them.  If the algorithm is NP
complete, then it will take a long time to do this.

The cliques-local-optima variant includes an additional certification
from the target to a-0, which will trip up simple heuristics.

For added fun, we also add a local optimum in the -local-optimum
variant:

  - root -- 200/30 --> a1
  - root -- 255/30 --> b0

And a second local optimum in the -local-optimum-2 variant:

  - b1 -- 255/30 --> c1

```
          root ----------------------+-.
 100/120   |                         | |
           |                  200/30 | | 255/30
           v                         | |
           a0  a9  a8  a7  a6        | |
             \  |   |  /  /          | |
 100/120         Clique              | |
             /  |   |  \  \          | |
           a1 _a2  a3  a4  a5        | |
           | |\.---------------------' |
 100/120   |   .-----------------------'
           v |/_
           b0  b9  b8  b7  b6
             \  |   |  /  /
 100/120         Clique
             /  |   |  \  \
           b1  b2  b3  b4  b5
 100/120   | \---------------------.
           v                       |
           c0  c9  c8  c7  c6      |
             \  |   |  /  /        | 255/30
 100/120         Clique            |
             /  |   |  \  \        |
           c1  c2  c3  c4  c5      |
 100/120   | \---------------------'
           v
           d0  d9  d8  d7  d6
             \  |   |  /  /
 100/120         Clique
             /  |   |  \  \
           d1  d2  d3  d4  d5
 100/120   |
           v
           e0
 100/120   |
           v
           f0
 100/120   |
           v
         target
```
