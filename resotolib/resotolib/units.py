import pint

from pint import Unit, Quantity

reg = pint.UnitRegistry()

# Xi bytes are not known to pint
reg.define("Ei = 1 EiB")
reg.define("Pi = 1 PiB")
reg.define("Ti = 1 TiB")
reg.define("Gi = 1 GiB")
reg.define("Mi = 1 MiB")
reg.define("Ki = 1 KiB")
reg.define("KB = 1000 B")

# globally define or register units

bytes_u: Unit = reg.byte


def parse(s: str) -> Quantity:
    return reg(s)
