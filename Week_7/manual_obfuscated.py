_ = lambda x: x if x < 2 else _(x-1) + _(x-2)
exec("print('Fibonacci(10) =', _(10))")
