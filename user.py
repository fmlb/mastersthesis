import asyncio
import asyncio.streams
import numpy
import scipy.stats as stat
from petlib.ec import EcPt
from base64 import b64encode
from petlib.pack import encode, decode
from binascii import hexlify

import time
from genzkp import *

loop = asyncio.get_event_loop()

class StateHolder(object):
    pass


@asyncio.coroutine
def client(name, Age):
    reader, writer = yield from asyncio.streams.open_connection(
        '127.0.0.1', 12345, loop=loop)#Service Provider
    reader2, writer2 = yield from asyncio.streams.open_connection(
        '127.0.0.1', 7878, loop=loop)#Identity Provider

    def send(msg, writer):
        print("> " + str(msg))
        writer.write((msg + '\n').encode("utf-8"))
        print(msg)
        print(type(msg.encode("utf8")))

    def sendBin(data, writer):
        writer.write(data + b'done')

    def recv(reader):
        msgback = (yield from reader.readline()).decode("utf-8").rstrip()
        return msgback


    if True:

        sendBin(b'para', writer2)

        seri_enc_idp_pub = yield from reader2.readuntil(separator=b'done')
        if seri_enc_idp_pub[0:4] == b'parp':

            idp_pub, params = decode(seri_enc_idp_pub[4:-4])
            G, q, g, h, z, hs = params

        #we generate our master secret, or private key
        masterSecret = q.random()

        #encode and send user_commit to idp
        LT_user_state, user_commit = BL_user_setup(params, [masterSecret, Age])


        C = LT_user_state.C
        R = LT_user_state.R

        #we compute a challenge and the responses for the ZK with the identity provider
        c, responses = ZK_idprov(C, R, params, masterSecret)

        #these are the values we wish to send to the identity provider
        values = (user_commit, c, responses, name, Age)

        sendBin(b'ucmt' + encode(values), writer2)

        msg2 = yield from reader2.readuntil(separator=b'done')

        msg_to_user = decode(msg2[:-4])

        #begin preparation phase
        BL_user_prep(LT_user_state, msg_to_user)

        #inform idp Im prepped and ready to go
        sendBin(b'prep', writer2)

        msg3 = yield from reader2.readuntil(separator=b'done')

        msg_to_user2 = decode(msg3[:-4])

        #generate message to idp
        msg_to_idp = BL_user_validation(LT_user_state, idp_pub, msg_to_user2)

        #encode and send msg to idp
        sendBin(b'msgi' + encode(msg_to_idp), writer2)

        #receive last message from idp, generate signature

        msg4 = yield from reader2.readuntil(separator=b'done')

        msg_to_user3 = decode(msg4[:-4])

        sig = BL_user_validation_2(LT_user_state, msg_to_user3)

        signature_gamhs = BL_user_prove_cred(LT_user_state)
        signature = signature_gamhs[0]
        gam_hs = signature_gamhs[1]
        gam_g = signature_gamhs[2]

        signatures = (sig, signature)

        #SEND CREDENTIAL

        sendBin(b'vsig' + encode(signatures) + b'done', writer)

        zet1p = LT_user_state.zet1 - Age * gam_hs[2]

        #PROVE AGE

        #get variables needed for the proof
        rnd = LT_user_state.rnd
        R = LT_user_state.R
        H = G.hash_to_point(b'name')  #this is the service provider's name
        ID = masterSecret * H  #this is our pseudonym

        c, responses = ZK_servprov(rnd, R, H, ID, params, zet1p, masterSecret, gam_g, gam_hs)
        newStuff = (c, responses, gam_g, gam_hs, Age, ID)

        sendBin(b'page' + encode(newStuff) + b'done', writer)

        confirmation = yield from reader.readuntil(separator=b'done')

        if confirmation[0:4] == b'okay':
            print('Verification succesful')
        elif confirmation[0:4] == b'fail':
            print('Verification failed')

    #close our connections to the identity and service providers
    writer.close()
    writer2.close()

def BL_user_setup(params, attributes):
    (G, q, g, h, z, hs) = params

    R = q.random()
    C = R * hs[0]

    for (i, attrib_i) in enumerate(attributes):
        C = C + attrib_i * hs[1+i]

    user_state = StateHolder()
    user_state.params = params
    user_state.attributes = attributes
    user_state.C = C
    user_state.R = R

    return user_state, (C, )

def BL_user_prep(user_state, msg_from_idp):
    (G, q, g, h, z, hs) = user_state.params
    (rnd, ) = msg_from_idp
    C = user_state.C

    z1 = C + rnd * g
    gam = q.random()
    zet = gam * z
    zet1 = gam * z1
    zet2 = zet + (-zet1)
    tau = q.random()
    eta = tau * z

    user_state.z1 = z1
    user_state.gam = gam
    user_state.zet = zet
    user_state.zet1 = zet1
    user_state.zet2 = zet2
    user_state.tau = tau
    user_state.eta = eta

    user_state.rnd = rnd

def BL_user_validation(user_state, idp_pub, msg_to_user, message=b''):
    (G, q, g, h, z, hs) = user_state.params
     # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state
    (a, a1p, a2p) = msg_to_user
    (y,) = idp_pub

    assert G.check_point(a)
    assert G.check_point(a1p)
    assert G.check_point(a2p)

    t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
    alph = a + t1 * g + t2 * y
    alph1 = user_state.gam * a1p + t3 * g + t4 * user_state.zet1
    alph2 = user_state.gam * a2p + t5 * h + t4 * user_state.zet2

    # Make epsilon
    H = [user_state.zet, user_state.zet1, alph, alph1, alph2, user_state.eta]
    Hstr = list(map(EcPt.export, H)) + [message]
    Hhex = b"|".join(map(b64encode, Hstr))
    epsilon = Bn.from_binary(sha256(Hhex).digest()) % q

    e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

    user_state.ts = [t1, t2, t3, t4, t5]
    user_state.message = message

    msg_to_issuer = e
    return msg_to_issuer

def BL_user_validation_2(user_state, msg_from_idp):
    (G, q, g, h, z, hs) = user_state.params
    (c, r, cp, r1p, r2p) = msg_from_idp
    (t1,t2,t3,t4,t5), m = user_state.ts, user_state.message

    # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state

    gam = user_state.gam

    ro = r.mod_add(t1,q)
    om = c.mod_add(t2,q)
    ro1p = (gam * r1p + t3) % q
    ro2p = (gam * r2p + t5) % q
    omp = (cp + t4) % q
    mu = (user_state.tau - omp * gam) % q

    signature = (m, user_state.zet,
                    user_state.zet1,
                    user_state.zet2, om, omp, ro, ro1p, ro2p, mu)

    return signature

def BL_cred_proof(user_state):
    (G, q, g, h, z, hs) = user_state.params
    gam = user_state.gam

    assert user_state.zet == user_state.gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g

    Cnew = user_state.rnd * gam_g + user_state.R * gam_hs[0]
    for i, attr in enumerate(user_state.attributes):
        Cnew = Cnew + attr * gam_hs[1+i]

    assert Cnew == user_state.zet1

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

def BL_user_prove_cred(user_state):
    (G, q, g, h, z, hs) = user_state.params
    zk = BL_show_zk_proof(user_state.params, len(user_state.attributes))

    env = ZKEnv(zk)

    # The secrets
    env.gam = user_state.gam
    env.rnd = user_state.rnd
    env.R   = user_state.R
    env.attrib = user_state.attributes

    # Constants
    env.g = g
    env.z = z
    env.zet = user_state.zet
    env.zet1 = user_state.zet1
    env.hs = hs[:len(user_state.attributes) + 1]

    # The stored generators
    env.gamg = gam_g = user_state.gam * g
    env.gamhs = gam_hs = [user_state.gam * hsi for hsi in hs[:len(user_state.attributes) + 1]]

    ## Extract the proof
    sig = zk.build_proof(env.get())
    if __debug__:
        assert zk.verify_proof(env.get(), sig, strict=False)

    return sig, gam_hs, gam_g


def ZK_idprov(C, R, params, masterSecret):
    G, q, g, h, z, hs = params

    wR_id = q.random()
    wx_id = q.random()

    Wit = wR_id * hs[0] + wx_id * hs[1]  # might be wrong, h or h0?
    # WID_id = wx_id * H

    # stuffToHash = (Wit, WID_id, C, g, h, z, hs[0], hs[1], hs[2], hs[3], ID)
    stuffToHash = (Wit, C, g, h, z, hs[0], hs[1], hs[2], hs[3])
    cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
    chash = sha256(cstr).digest()
    c = Bn.from_binary(chash)

    rR_id = (wR_id - c * R) % q
    rx_id = (wx_id - c * masterSecret) % q
    responses = (rR_id, rx_id)
    return (c, responses)

def ZK_servprov(rnd, R, H, ID, params, zet1p, masterSecret, gam_g, gam_hs):

            G, q, g, h, z, hs = params

            wrnd = q.random()
            wR = q.random()
            wx = q.random()

            Wzet1p = wrnd * gam_g + wR * gam_hs[0] + wx * gam_hs[1]

            WID = wx * H

            stuffToHash = (gam_g, Wzet1p, WID, zet1p, gam_hs[0], gam_hs[1], gam_hs[2], ID)
            cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
            chash = sha256(cstr).digest()
            c = Bn.from_binary(chash)

            rrnd = (wrnd - c*rnd) % q
            rR = (wR - c*R) % q
            rx = (wx - c*masterSecret) % q

            responses = (rrnd, rR, rx)
            return c, responses

try:
    #specify how many users we want to run
    for _ in range(100):
        loop.run_until_complete(client(b'John', 21))
finally:
    loop.close()

