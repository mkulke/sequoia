The best path from A to F is: A - B - C - E - F.

Back propagation will choose: A - B - F (because it has more depth).

Make sure we don't choose A - B - D - E - F.

For G, A - B - C - E - G and A - B - D - E - G are equally good.  But,
we will select the latter, because when we have a choice, we prefer
more depth.

For H, A - B - C - E - H is better.

```
             A
             | 150/120
             v
             B -------------,
  50/100  /  |              |
         v   v 100/50       |
         C   D              |  200/75
  50/100  \  | 100/50       |
          _\|v              |
             o E --------   v
           /   \         `->F
    0/120 /     \ 0/30   100/120
         v       v
         H       G
```
