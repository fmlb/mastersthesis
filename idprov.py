import asyncio
import asyncio.streams

from petlib.ec import EcPt, EcGroup
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256
from binascii import hexlify


loop = asyncio.get_event_loop()


peopleTestList = {b'John':21, b'Nasos':22, b'Andreas':14, b'Tom':12, b'Anna':40, b'Maria':10}

class MyServer:

    def __init__(self):
        self.server = None

        self.clients = {}
        self.params = BL_setup()
        self.idp_priv, self.idp_pub = BL_idp_key(self.params)

    def sendParams(self):
        reader_sp, writer_sp = yield from asyncio.streams.open_connection("localhost", 12345, loop=loop)
        stuffToSend = (self.idp_pub, self.params)
        writer_sp.write(b'mypb' + encode(stuffToSend) + b'done')
        print("Sending parameters and public key to service provider")

    def _accept_client(self, client_reader, client_writer):

        # start a new Task to handle this specific client connection
        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            del self.clients[task]

        task.add_done_callback(client_done)


    @asyncio.coroutine
    def _handle_client(self, client_reader, client_writer):

        params = self.params
        idp_pub = self.idp_pub
        idp_priv = self.idp_priv

        G, q, g, h, z, hs = params

        while True:
            try:
                data = yield from client_reader.readuntil(separator=b'done')

                cmd = data[0:4]

                strippedData = data[4:-4]

            except asyncio.streams.IncompleteReadError:
                data = None
            if not data:  # an empty string means the client disconnected
                break

            if cmd == b'para':

                #A user has requested the parameters and public key

                stuff = (idp_pub, params)

                #compute initial state
                LT_idp_state = BL_idp_state(idp_priv, idp_pub, params)

                #send public key to user
                client_writer.write(b'parp' + encode(stuff) + b'done')



            elif cmd == b'ucmt':

                user_commit, c, responses, name, Age = decode(strippedData)

                #assert whether the user is who he says he is
                assert peopleTestList[name] == Age

                assert ZK_verify(user_commit[0], c, responses, Age, params) == True

                #generate and send message to user
                msg_to_user = BL_idp_prep(LT_idp_state, user_commit)

                client_writer.write(encode(msg_to_user) + b'done')

            elif cmd == b'prep':
                #begin preparation phase, generate and send second message
                msg_to_user2 = BL_idp_validation(LT_idp_state)

                client_writer.write(encode(msg_to_user2) + b'done')

            elif cmd == b'msgi':

                msg_to_idp = decode(strippedData)

                # generate 3rd message to user
                msg_to_user3 = BL_idp_validation_2(LT_idp_state, msg_to_idp)

                client_writer.write(encode(msg_to_user3) + b'done')

            # This enables us to have flow control in our connection.
            yield from client_writer.drain()

    def start(self, loop):

        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,'127.0.0.1', 7878, loop=loop))

    def stop(self, loop):

        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None


def send(msg, writer):
        print("> " + msg)
        writer.write((msg + '\n').encode("utf-8"))


class StateHolder(object):
    pass

def BL_setup(Gid = 713):
    G = EcGroup(Gid)
    q = G.order()

    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf-8")) for i in range(4)]#the number of generators we wish to compute

    return (G, q, g, h, z, hs)

def BL_idp_key(params):
    (G, q, g, h, z, hs) = params

    x = q.random()
    y = x * g

    return x, (y, )

def BL_idp_state(priv, pub, params):

    idp_state = StateHolder()
    idp_state.params = params
    idp_state.x = priv
    idp_state.y = pub[0]

    return idp_state

def BL_idp_keys(params):
    (G, q, g, h, z, hs) = params

    x = q.random()
    y = x * g

    idp_state = StateHolder()
    idp_state.params = params
    idp_state.x = x
    idp_state.y = y

    return idp_state, (y, )

def BL_idp_prep(idp_state, user_commit):
    (G, q, g, h, z, hs) = idp_state.params
    (x, y) = (idp_state.x, idp_state.y)

    (C, ) = user_commit

    rnd = q.random()
    z1 = C + rnd * g
    z2 = z + (-z1)

    #send
    if rnd % q == 0:
        raise

    idp_state.rnd = rnd
    idp_state.z1 = z1
    idp_state.z2 = z2

    message_to_user = (rnd, )

    return message_to_user


def BL_idp_validation(idp_state):
    (G, q, g, h, z, hs) = idp_state.params

    u, r1p, r2p, cp = [q.random() for _ in range(4)]
    a = u * g
    a1p = r1p * g + cp * idp_state.z1
    a2p = r2p * h + cp * idp_state.z2

    idp_state.u = u
    idp_state.r1p = r1p
    idp_state.r2p = r2p
    idp_state.cp = cp

    return (a, a1p, a2p)

def BL_idp_validation_2(idp_state, msg_from_user):
    (G, q, g, h, z, hs) = idp_state.params
    # x, y = key_pair
    # (u, r1p, r2p, cp) = issuer_val_private
    e = msg_from_user

    ## Send: (e,) to Issuer
    c = e.mod_sub(idp_state.cp, q)
    r = idp_state.u.mod_sub((c * idp_state.x), q)

    msg_to_user = (c, r, idp_state.cp, idp_state.r1p, idp_state.r2p)
    return msg_to_user

def ZK_verify(C, c, responses, Age, params):
    G, q, g, h, z, hs = params

    rR, rx = responses


    Cprime = C - Age * hs[2]

    Wprime = rR * hs[0] + rx * hs[1] + c * Cprime

    stuffToHash = (Wprime, C, g, h, z, hs[0], hs[1], hs[2], hs[3])
    cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
    chash = sha256(cstr).digest()
    cprime = Bn.from_binary(chash)

    return(c==cprime)


def main():
    loop = asyncio.get_event_loop()
    future = asyncio.Future()

    server = MyServer()
    loop.run_until_complete(server.sendParams())
    server.start(loop)


    try:
        loop.run_until_complete(future)
        server.stop(loop)
    finally:
        loop.close()


if __name__ == '__main__':
    main()