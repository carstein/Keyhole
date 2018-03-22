# Author: carstein <michal.melewski@gmail.com>
# Binary Fingerprint

import io
import base64

from hilbert import Hilbert
from PIL import Image, ImageDraw

scale = [(4,     2, 160), # elements, N-hilbert, size
         (16,    4, 80),
         (64,    8, 40),
         (256,  16, 20),
         (1024, 32, 10),
         (4096, 64, 5)]

color = {0:'#F9DEC9',
         1:'#33ADFF',
         2:'#3A405A',
         3:'#383D3B',
         4:'#E3170A'}


class FingerprintReport:
  t = [
        (['mov', 'lea', 'pop','push', 'movzx', 'movsxd'], 1),
        ([],2),
        (['and','xor','add', 'sub','mul','div', 'sar', 'shr', 'not'], 3),
        (['call', 'cmp', 'jle', 'ja','jg', 'jbe', 'test', 'je', 'jne', 'jmp', 'jl', 'jge'], 4),
      ]

  def __init__(self):
    self.fingerprint = []
    self.hilbert = None

  def reset(self):
    self.fingerprint = []

  def add(self, i):
    # Processing instruction
    for group, color in self.t:
      if i in group:
        self.fingerprint.append(color)
        return

    print 'unmatched instruction {}'.format(i)
    self.fingerprint.append(0)

  def create_image(self):
    img = Image.new("RGB", (320,320), '#FFFFFF')
    draw = ImageDraw.Draw(img)

    # Calculate sizes - box size and elements
    l = len(self.fingerprint)
    if 4 <= l <= 4096:
      for el, n, size in scale:
        if el >= l:
          self.size = size
          self.hilbert = Hilbert(n)
          break
    else:
      return None

    ## Create Image
    for idx, val in enumerate(self.fingerprint):
      x1,y1 = self.hilbert.position(idx, self.size)
      x2 = x1 + self.size - 1
      y2 = y1 + self.size - 1

      draw.rectangle([x1, y1, x2, y2], fill=color[val])

    ## Save image
    b = io.BytesIO()
    img.save(b, 'PNG')

    return base64.b64encode(b.getvalue())
