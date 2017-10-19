Bugs:
* Jmp et Return dans les boucles doivent en faire sortir. Attention au directives de default_unroll qui suit un jmp repne et à l'incr de esp après le ret qui doivent tout de même être exec
* caractère échappement des format string est le %
* mettre un message quand code dans rep/repe/repne n'est pas stos/scas/etc.

Hard:
* use a shared data structure to store memory only once for all states
* mem deref with taint in displacement expression
* multiplication when only one operand is tainted
