import pint

from pint import Unit, Quantity

reg = pint.UnitRegistry()

# Xi bytes are not known to pint
reg.define("Ei = 1 EiB")  # type: ignore
reg.define("Pi = 1 PiB")  # type: ignore
reg.define("Ti = 1 TiB")  # type: ignore
reg.define("Gi = 1 GiB")  # type: ignore
reg.define("Mi = 1 MiB")  # type: ignore
reg.define("Ki = 1 KiB")  # type: ignore
reg.define("KB = 1000 B")  # type: ignore

# globally define or register units

bytes_u: Unit = reg.byte


def parse(s: str) -> Quantity:
    return reg(s)
