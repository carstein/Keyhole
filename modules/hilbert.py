# Author: carstein <michal.melewski@gmail.com>
# Hilbert curve

class Hilbert:
  def __init__(self, n):
    self.size = n

  @staticmethod
  def last2bits(x):
    return x & 3

  def position(self, p, mul=1):
    x,y = 0,0

    for n in [2**i for i in range(1, self.size)]:

      t = Hilbert.last2bits(p)
      if t == 0:
        x,y = y,x
      elif t == 1:
        y += n/2
      elif t == 2:
        x += (n/2)
        y += (n/2)
      else:
        x,y = (n/2)-1-y+(n/2), (n/2)-1-x

      p = p >> 2

    return x*mul, y*mul
