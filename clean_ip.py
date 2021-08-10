from ipaddress import ip_address
from typing import Any
import numpy as np


def _format_ip(val: Any, input_format: str, output_format: str, errors: str) -> Any:
    address, status = _check_ip(val, input_format, True)

    if status == "null":
        return np.nan, 0
    if status == "unknown":
        if errors == "raise":
            raise ValueError(f"Unable to parse value {val}")
        return val if errors == "ignore" else np.nan, 1

    # compressed version without the leading zeros (for ipv6 double colon for zeros)
    if output_format == "compressed":
        result = address.compressed

    # Converts the integer repesentation of the ip address to its hexadecimal
    # form. Does not contain any dots or colons.
    elif output_format == "hexa":
        result = hex(int(address))

    # converts the ip address to its binary representation
    elif output_format == "binary":
        if address.version == 4:
            result = "{0:032b}".format(int(address))
        else:
            result = "{0:0128b}".format(int(address))

    # converts to integer format
    elif output_format == "integer":
        result = int(address)

    # convert to full representation
    else:
        dlm = "." if address.version == 4 else ":"  # delimiter
        result = dlm.join(f"{'0' * (4 - len(x))}{x}" for x in address.exploded.split(dlm))

    return result, 2 if result != val else 3


def _check_ip(val: Any, input_format: str, clean: bool) -> Any:
    """
    Function to check whether a value is valid ip address
    """
    try:
        if val is None:
            return (None, "null") if clean else False

        address = ip_address(val)
        vers = address.version

        if vers == 4 and input_format != "ipv6" or vers == 6 and input_format != "ipv4":
            return (address, "success") if clean else True
        return (None, "unknown") if clean else False

    except (TypeError, ValueError):
        return (None, "unknown") if clean else False