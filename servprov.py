
import asyncio
import asyncio.streams
from petlib.ec import EcPt
from petlib.pack import decode
from binascii import hexlify
from genzkp import *
from base64 import b64encode

class MyServer:

    def __init__(self):
        self.server = None
        #keeps track of clients
        self.clients = {} # task -> (reader, writer)

    def _accept_client(self, client_reader, client_writer):

        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            del self.clients[task]

        task.add_done_callback(client_done)

    @asyncio.coroutine
    def _handle_client(self, client_reader, client_writer):

        while True:
            try:
                data = yield from client_reader.readuntil(separator=b'done')

                cmd = data[0:4]

                strippedData = data[4:-4]

            except asyncio.streams.IncompleteReadError:
                data = None
            if not data: # an empty string means the client disconnected
                break

            if cmd == b'mypb':
                self.idp_pub, self.params = decode(strippedData)
                print("Parameters and idp's public key received")

            elif cmd == b'vsig':

                sig, signature = decode(strippedData)

                params = self.params
                idp_pub = self.idp_pub

                #assert the validity of the credential
                m = BL_verify_cred(params, idp_pub, 2, sig, signature)

                if m != False:
                    print('Signature Correct')
                else:
                    print('Signature Incorrect')

            elif cmd == b'page':

                newStuff = decode(strippedData)
                c, responses, gam_g, gam_hs, Age, ID = newStuff

                zet1 = sig[2]

                #assert user's age is correct
                if ZK_verify_age(c, responses, gam_g, gam_hs, Age, ID, params, zet1) == True:
                    print("Age & User verified")
                    client_writer.write(b'okaydone')
                else:
                    print("Proof failed")
                    client_writer.write(b'faildone')


            # This enables us to have flow control in our connection.
            yield from client_writer.drain()

    def start(self, loop):

        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,
                                         '127.0.0.1', 12345,
                                         loop=loop))

    def stop(self, loop):

        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None


def BL_show_zk_proof(params, num_attrib):
    (G, _, _, _, _, _) = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables

    gam, rnd, R = zk.get(Sec, ["gam", "rnd", "R"])
    attrib = zk.get_array(Sec, "attrib", num_attrib, 0)

    g, z, zet, zet1 = zk.get(ConstGen, ["g", "z", "zet", "zet1"])
    hs = zk.get_array(ConstGen, "hs", num_attrib+1, 0)

    zk.add_proof(zet, gam * z)

    gam_g = zk.get(Gen, "gamg")
    zk.add_proof(gam_g, gam * g)

    gam_hs = zk.get_array(Gen, "gamhs", num_attrib+1, 0)

    for gam_hsi, hsi in zip(gam_hs, hs):
        zk.add_proof(gam_hsi, gam * hsi)

    Cnew = rnd * gam_g + R * gam_hs[0]
    for i, attr in enumerate(attrib):
        Cnew = Cnew + attr * gam_hs[1+i]

    zk.add_proof(zet1, Cnew)
    return zk

def BL_check_signature(params, idp_pub, signature):
    (G, q, g, h, z, hs) = params
    (y,) = idp_pub
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    lhs = (om + omp) % q
    rhs_h = [zet, zet1,
            ro * g + om * y,
            ro1p * g + omp * zet1,
            ro2p * h + omp * zet2, ## problem
            mu * z + omp * zet]

    Hstr = list(map(EcPt.export, rhs_h)) + [m]
    Hhex = b"|".join(map(b64encode, Hstr))
    rhs = Bn.from_binary(sha256(Hhex).digest()) % q

    if rhs == lhs:
        return m
    else:
        return False

def BL_verify_cred(params, issuer_pub, num_attributes, signature, sig):
    m = BL_check_signature(params, issuer_pub, signature)
    assert m != False

    (G, q, g, h, z, hs) = params
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    zk = BL_show_zk_proof(params, num_attributes) #we get this from the user

    env = ZKEnv(zk)

    # Constants
    env.g = g
    env.z = z
    env.zet = zet
    env.zet1 = zet1
    env.hs = hs[:num_attributes + 1]

    ## Extract the proof
    res = zk.verify_proof(env.get(), sig)
    assert res

    return m


def ZK_verify_age(c, responses, gam_g, gam_hs, Age, ID, params, zet1):
    rrnd, rR, rx = responses

    (G, q, g, h, z, hs) = params

    H = G.hash_to_point(b'name')

    zet1p = zet1 - Age * gam_hs[2]

    Waprime = rrnd * gam_g + rR * gam_hs[0] + rx * gam_hs[1] + c * zet1p

    Wxprime = rx * H + c * ID

    stuffToHash = (gam_g, Waprime, Wxprime, zet1p, gam_hs[0], gam_hs[1], gam_hs[2], ID)
    cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
    chash = sha256(cstr).digest()
    c_prime = Bn.from_binary(chash)

    return (c == c_prime)

def main():
    global paramsReceived
    global count
    paramsReceived = False
    count = 0
    loop = asyncio.get_event_loop()
    future = asyncio.Future()

    server = MyServer()
    server.start(loop)

    try:
        loop.run_until_complete(future)
        server.stop(loop)
    finally:
        loop.close()


if __name__ == '__main__':
    main()