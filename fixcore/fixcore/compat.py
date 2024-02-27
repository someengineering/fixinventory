import sys

# All python version specific differences are listed here


# string.removesuffix is introduced in 3.9
if sys.version_info < (3, 9):

    def remove_suffix(s: str, suffix: str) -> str:
        if s.endswith(suffix):
            return s[: -len(suffix)]
        else:
            return s

else:

    def remove_suffix(s: str, suffix: str) -> str:
        return s.removesuffix(suffix)
