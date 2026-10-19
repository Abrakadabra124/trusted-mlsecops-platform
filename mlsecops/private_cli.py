import argparse

from mlsecops.contracts import Rejected


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("cli_arguments_invalid")
