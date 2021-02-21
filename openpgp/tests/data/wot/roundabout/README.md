The best way from A to B, G and H is via C-D-E-F.  The best way from A
to I is via B!  (A has two local optima.)

J complicates things a bit when doing a backwards propagation.

```
        A
        | \  6,120
        |  C
        |  |  5,120
        |  D
100,60  |  |  4,120      5,100
        |  E <----------------- J
        |  | 3,120              |
        |  F                    |
        v /  2,120              | 1,100
        B                       |
 2,120  |                       |
        v                       |
        G <---------------------'
 1,120  |
        v
        H
 0,120  |
        v
        I
```
