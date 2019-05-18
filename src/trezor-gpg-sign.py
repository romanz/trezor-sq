#!/usr/bin/env python3
import os
import sys

from trezorlib.client import TrezorClient
from trezorlib.transport import get_transport
from trezorlib.messages import IdentityType
from trezorlib.ui import ClickUI

from trezorlib.misc import sign_identity

def main():
    host, = sys.argv[1:]
    transport = get_transport(os.environ.get("TREZOR_PATH"))
    identity_proto = IdentityType(proto='gpg', host=host)
    client = TrezorClient(transport=transport, ui=ClickUI(), state=None)

    digest = sys.stdin.buffer.read()
    assert len(digest) == 64, len(digest)

    result = sign_identity(
        client=client,
        identity=identity_proto,
        challenge_hidden=digest,
        challenge_visual='',
        ecdsa_curve_name='ed25519')

    assert len(result.signature) == 65, result
    assert result.signature[:1] == b'\x00'
    sig = bytes(result.signature[1:])

    sys.stdout.buffer.write(sig)

if __name__ == '__main__':
    main()
