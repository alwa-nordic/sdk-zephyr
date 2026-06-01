.. _bluetooth_le_oob:

LE Out of Band Pairing
######################

This document explains how Out of Band (OOB) data is used during LE pairing,
how the two flavours of OOB pairing differ, what the OOB channel actually has
to guarantee, and what that means in practice for common product setups
(for example a peripheral with a readable NFC tag, or a device with a printed
QR code). It also covers a corner case for centrals that ship a printed
OOB code and want to support both LE Legacy and LE Secure Connections (LESC)
pairing simultaneously, and what an application needs to do to make that
work.

This is not a tutorial for writing OOB-pairing-capable applications. For the
API surface, see :c:func:`bt_le_oob_get_local`, :c:func:`bt_le_oob_set_sc_data`,
:c:func:`bt_le_oob_set_legacy_tk`, :c:func:`bt_le_oob_set_sc_flag` and
:c:func:`bt_le_oob_set_legacy_flag`.

Background: the two OOB methods
*******************************

There are two LE pairing methods that consume OOB data, and they are
fundamentally different cryptographic protocols that happen to share a name
and a single bit on the wire.

LE Legacy OOB
=============

Legacy pairing predates LE Secure Connections. The OOB authentication method
in legacy pairing uses a single 128-bit value, the Temporary Key (TK), which
both peers must possess by the time SMP starts. The OOB channel is the
mechanism by which one peer's TK arrives at the other peer.

In legacy OOB the TK is the entire authentication secret. It is fed directly
into the legacy ``c1`` confirm-value calculation that both sides exchange
during pairing. If TK is wrong on either side, the confirms mismatch and
pairing fails. If TK is known to a third party, that party can complete a
MITM against the pairing.

LE Secure Connections OOB
=========================

LESC OOB is a different protocol. It does not use a shared secret. Instead,
each peer computes a commitment to its own ECDH public key by combining the
public key with a fresh random nonce ``r``::

    Cb = f4(PKa, PKa, r, 0)

The OOB channel carries the pair ``(r, Cb)`` from one peer to the other.
The receiving peer stores it. During pairing, after the public-key exchange,
the receiving peer recomputes ``f4(received PKa, received PKa, r, 0)`` and
checks that it matches the ``Cb`` it received over OOB. If it matches, the
receiver knows the public key it just got over the air really does belong to
the device it scanned (or tapped, or whatever the OOB channel was).

LESC OOB never uses ``r`` or ``Cb`` as a key. The session key is derived from
the ECDH exchange, which always runs. ``(r, Cb)`` is purely a binding
authenticator for the public key.

Channel security: integrity vs confidentiality
**********************************************

This is where the two methods diverge most sharply, and it is the property
that determines whether a given OOB medium is actually safe for a given
method.

Legacy OOB needs a confidential channel
=======================================

The TK is a key. Anyone who reads it can complete a MITM against any pairing
that uses it. So the OOB channel for legacy OOB must keep the TK
confidential: only the intended peer must be able to read it.

This rules out broadcast or passive channels for legacy OOB. A QR code on a
product box is readable by anyone who points a camera at it. Print a TK on a
sticker and any attacker who walks past has the secret. NFC is generally
considered close-proximity enough to be acceptable but the surface is still
broadcasting in the clear, so if an attacker can get an antenna close to the
tap, they have the TK.

LESC OOB only needs an integrity-protected channel
==================================================

``(r, Cb)`` does not need to be secret. ``r`` is a public nonce. ``Cb`` is a
public hash of public values. An attacker who reads them learns nothing they
could not learn by sniffing the air during pairing. What the attacker must
not be able to do is *modify* them in flight: if they can substitute their
own ``(r', Cb')`` they can substitute their own public key into the pairing
and become a MITM.

So the OOB channel for LESC OOB only needs to give the receiver assurance
that what it reads really came from the intended peer and was not tampered
with. Reading is fine. A QR code printed on a product is fine: the user can
see that the code is on the product and not on a sticker an attacker put
there. NFC is fine. A document the user types in is fine.

In practice this means LESC OOB is suitable for a wider range of channels
than legacy OOB, including passive ones.

Freshness: must the OOB data be regenerated per pairing?
********************************************************

Legacy TK: yes, the spec requires it
====================================

Bluetooth Core Specification Vol 3, Part H, section 2.3.5.4 says the TK
"shall be a 128-bit random number." The intent is that each pairing draws a
fresh TK; reusing a TK across pairings means an attacker who learns it once
can MITM future pairings.

This requirement has been part of the spec since the introduction of legacy
OOB, but the qualification process started actively testing it (in test
cases like ``SM/CEN/OOB/BV-10-C`` and ``SM/PER/OOB/BV-11-C``) more recently.
Older PTS versions accept a fixed TK that matches the
``TSPX_OOB_Data`` PIXIT; current PTS versions request a fresh TK from the
IUT for each pairing iteration and verify it changed. Products targeting
recent qualification therefore must generate a fresh TK per pairing in the
application layer and pass it to the stack via :c:func:`bt_le_oob_set_legacy_tk`
(or the equivalent BTP path during testing).

Static-TK products are stuck on older Bluetooth versions for qualification
purposes. They are also insecure in practice for the reasons above.

LESC ``r``: also random per pairing by spec, with a caveat
==========================================================

Vol 3, Part H, section 2.3.5.6.4 defines ``r`` as a 128-bit random number
generated for OOB authentication. Generating it freshly for every pairing
gives a unique ``Cb`` per pairing and is what the Zephyr stack does by
default. Each call to :c:func:`bt_le_oob_get_local` generates a fresh
``(r, Cb)`` pair, unless :kconfig:option:`CONFIG_BT_OOB_DATA_FIXED` is
enabled (see :zephyr_file:`subsys/bluetooth/host/smp.c`).

Unlike legacy TK, however, freshness of ``r`` is not a confidentiality
requirement. ``r`` is public. The freshness requirement on ``r`` is about
preventing replay of the OOB binding across pairings: if ``r`` is fixed and
the public key is fixed, then ``Cb`` is fixed, and the OOB binding becomes a
static credential. That is a real loss compared to per-pairing freshness,
but it is not the same as leaking a key.

This is what makes static LESC OOB (a printed QR code) cryptographically
viable in a way that static legacy OOB is not. The tradeoffs are discussed
below.

Typical setups
**************

Bidirectional NFC
=================

The textbook OOB setup. The two devices physically tap, both NFC stacks
exchange OOB data in both directions, and SMP is then triggered with both
peers having each other's data.

* For LESC OOB this gives ``BT_CONN_OOB_BOTH_PEERS``: each side has the
  other's ``(r, Cb)`` and can authenticate the other's public key. This is
  the strongest LESC OOB configuration. See the ``oob_config`` field of
  :c:struct:`bt_conn_oob_info` for the possible values.
* For legacy OOB this gives both sides the same TK, generated by whichever
  side decided to be the TK source.

Either method works. NFC is short-range enough that confidentiality of
legacy TK is generally acceptable in practice, and the bidirectional nature
satisfies legacy OOB's symmetric requirement naturally.

Read-only NFC tag on a peripheral
=================================

A passive NFC tag (no MCU connected) on a peripheral is one-way: the peer
reads the peripheral's OOB data, the peripheral has no way to know what the
peer's data would be, because there is no return path. This is unidirectional
LESC OOB.

* LESC OOB handles this: the OR-gate in method selection is enough to land
  on ``LE_SC_OOB`` even with only one side providing data. The peer has the
  peripheral's ``(r, Cb)`` and authenticates the peripheral's public key.
  The peripheral does not authenticate the peer's public key over OOB; it
  has only Just-Works-equivalent assurance about the peer.
* Legacy OOB does not handle this. Legacy OOB requires both sides to share
  the TK; if only the peripheral's TK leaves the peripheral and the
  peripheral has no way to learn whether the peer received it, there is no
  mechanism to converge on a shared TK.

If the OOB channel is one-way, only LESC OOB is viable. Legacy OOB needs at
minimum a way for the source to confirm the destination got the data, even
if the data itself only flows one way.

Static QR code (printed on the product)
=======================================

The QR code carries OOB data that is fixed at manufacturing time and
identical across the entire production run of a given device unit. The user
scans the code with the peer (typically a phone). The peripheral has no
scanner.

This is unidirectional and passive. Legacy OOB and LESC OOB diverge sharply
here.

Static legacy QR is broken
--------------------------

If the QR code is the legacy TK, then:

* The TK is a key. Anyone who has ever seen the QR has the TK forever. A
  photograph of the unboxed product, a publicly visible installation, a
  shared family-room device, all leak the TK.
* The TK does not change. Future pairings use the same TK. Future MITMs
  against the device by anyone who saw the QR are trivial.
* Modern qualification tests verify the TK is fresh per pairing. A static
  TK fails these tests.

A static legacy OOB QR code is therefore both insecure and not qualifiable
against current Bluetooth versions. Avoid this design.

Static LESC QR is workable, with caveats
----------------------------------------

If the QR code is LESC ``(r, Cb)``, then:

* ``r`` and ``Cb`` are public values. Anyone reading the QR learns nothing
  cryptographically useful. There is no key in the QR.
* The QR authenticates the device's *ECDH public key*. So the device must
  use the *same* public key for every pairing the QR is meant to
  authenticate. If the public key rotates, ``Cb`` no longer matches and the
  OOB authentication fails.
* Each pairing still runs a fresh ECDH exchange and derives a fresh session
  key. Forward secrecy of the session is preserved even though ``(r, Cb)``
  is static.

The privacy cost is real: a device that uses a static ECDH public key is
trivially identifiable across pairings, regardless of address randomization.
The QR effectively publishes a long-lived device identity. This may or may
not be acceptable for the product class. A medical or industrial device
where the user already knows which device they own probably does not care.
A consumer wearable that wants to be unlinkable to a specific user may care
a lot.

.. note::

   The Zephyr Bluetooth Host does not currently expose a public API for
   pinning the LESC ECDH public key to an application-supplied value. The
   stack generates a fresh keypair on stack initialization (see
   :zephyr_file:`subsys/bluetooth/host/ecc.c`), and there is no
   ``bt_pub_key_set`` equivalent. :kconfig:option:`CONFIG_BT_USE_DEBUG_KEYS`
   uses the spec-defined debug keypair, which is publicly known and
   provides no MITM protection.

   Building a static-LESC-QR product on Zephyr therefore requires either an
   out-of-tree patch to the host, or generating the keypair, computing
   ``(r, Cb)``, baking them into the device's persistent storage, and
   replacing the host's keypair generation path. None of this is
   first-class today. The :kconfig:option:`CONFIG_BT_OOB_DATA_FIXED` option
   pins ``r`` to a hardcoded value but is documented for testing only and
   does not solve the public-key-pinning half of the problem.

Static LESC QR is the only static-OOB design that is cryptographically
defensible. Static legacy QR is not.

The OOB present flag and pairing method selection
*************************************************

SMP has a single ``OOB present`` bit in the Pairing Request and Pairing
Response messages. Its meaning depends on the pairing mode:

* In legacy pairing it means "I have the shared TK".
* In LESC pairing it means "I have the peer's OOB data (their ``(r, Cb)``)".

Both peers' bits feed into method selection, but the rules are not the same:

* LESC OOB is selected if **either** side has the bit set (OR-gate). This
  is correct: LESC OOB authenticates one direction at a time, so a single
  side having the peer's OOB data is enough to do useful work.
* Legacy OOB is selected only if **both** sides have the bit set
  (AND-gate). This is correct: legacy OOB requires a shared TK, which is
  only possible if both sides have it.

The relevant code is in :zephyr_file:`subsys/bluetooth/host/smp.c`:
``get_pair_method()`` and ``legacy_get_pair_method()``.

The peripheral picks the right flag because by the time it builds the
Pairing Response, it already knows whether SC was negotiated (the peer's
``auth_req`` is in the Pairing Request, which the peripheral has just
parsed). The central does not have this luxury: when it builds the Pairing
Request, it has not yet seen the peer's capabilities, so it has to commit
to a flag value blind. The Zephyr stack handles this by OR-ing both local
flags::

    /* At this point is it unknown if pairing will be legacy or LE SC so
     * set OOB flag if any OOB data is present and assume to peer device
     * provides OOB data that will match it's pairing type.
     */
    req->oob_flag = (legacy_oobd_present || sc_oobd_present) ?
                            BT_SMP_OOB_PRESENT : BT_SMP_OOB_NOT_PRESENT;

The comment is doing load-bearing work: the central is trusting the
application to have set the flags only if matching data really is available.

Corner case: central with both legacy and LESC OOB
**************************************************

Consider a central that ships with a printed OOB code (or two printed
codes) and supports both legacy and LESC pairing. The central has no
scanner, so it cannot read anything from the peer. The two pairing flavours
have different requirements on the central's side:

* Legacy: for legacy OOB to be selected, the central must set its OOB-flag.
  The TK itself is the printed value, which the peer reads.
* LESC: the central does not have the peer's ``(r, Cb)``. It has nothing
  from the peer. By the LESC OOB definition, the central's OOB flag should
  be **clear**: it does not have peer OOB data.

The single OOB-flag bit on the wire cannot represent both states. If the
application sets ``legacy_oobd_present = true`` so legacy OOB pairings can
work, the central sends Pairing Request with OOB present. If pairing then
negotiates LESC, the OR-gate triggers on the central's flag alone and method
selection lands on ``LE_SC_OOB``. The central has no LESC OOB data to
provide. The peer may or may not have read the LESC OOB code (if there is
one). If the peer also has no LESC OOB data, the pairing fails with no
fallback.

The four-way truth table for a dual-OOB central with the legacy flag set:

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - Negotiated mode
     - Peer scanned legacy OOB
     - Peer scanned LESC OOB
     - Outcome
   * - Legacy
     - Yes
     - n/a
     - ``LEGACY_OOB`` succeeds
   * - Legacy
     - No
     - n/a
     - Falls back to non-OOB legacy (Just Works or passkey)
   * - LESC
     - n/a
     - Yes
     - ``LE_SC_OOB`` succeeds (peer has central's ``(r, Cb)``)
   * - LESC
     - n/a
     - No
     - ``LE_SC_OOB`` selected, no data on either side, **pairing fails**

The last row is the failure mode. The legacy flag's presence on the central
forces LESC OOB selection in cases where neither side has LESC OOB data.

There is no purely-stack solution. The OOB present bit is a single bit on
the wire and the stack has no way to know what the peer has read until the
peer responds. Working solutions all involve adding a side channel between
the application layers of the two peers so the central can decide which
flag(s) to set before it sends the Pairing Request.

A pre-pairing GATT handshake
============================

The application can define a vendor-specific GATT characteristic on the
central that the peer writes before triggering pairing. The characteristic
value indicates which OOB data the peer has scanned and which mode it
intends:

* If the peer writes "I scanned legacy QR", the central sets
  ``legacy_oobd_present = true``, leaves ``sc_oobd_present`` clear, and
  expects to negotiate legacy.
* If the peer writes "I scanned LESC QR", the central sets
  ``sc_oobd_present`` (or leaves both clear; LESC OOB only requires the
  peer's flag) and expects to negotiate LESC.
* If no write arrives, the central leaves both flags clear and falls back
  to non-OOB pairing.

This is what real products that ship printed OOB codes typically do, in one
form or another. The OOB channel itself (QR) is unidirectional and carries
data; the GATT characteristic is the bidirectional intent channel that
tells the central what the OOB transfer accomplished.

The GATT round-trip costs negligible time before pairing and avoids the
unrecoverable failure mode above. Without it, a dual-OOB central has to
pick a flavour to support and drop the other.

Alternative: drop legacy OOB
============================

If supporting both flavours is not a hard requirement, the simplest
mitigation is to ship only the LESC QR code and not advertise legacy OOB at
all. Modern peers all support LESC; legacy OOB is largely a holdover for
SC-incapable peers, and those peers will fall back gracefully to non-OOB
legacy pairing (Just Works or passkey) anyway. A dual-OOB design only
benefits products that genuinely need authenticated pairing with SC-incapable
peers, which is a shrinking set.

Configuration reference
***********************

The Kconfig surface for OOB-related behaviour:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Kconfig option
     - Effect
   * - :kconfig:option:`CONFIG_BT_SMP_SC_PAIR_ONLY`
     - Disables legacy pairing entirely. Default ``y``. Removes the
       central-side flag-asymmetry concern (no legacy code path remains)
       and is correct for products that only target LESC peers.
   * - :kconfig:option:`CONFIG_BT_SMP_SC_ONLY`
     - Enforces Security Mode 1 Level 4. Stricter superset of
       ``BT_SMP_SC_PAIR_ONLY``.
   * - :kconfig:option:`CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY`
     - Disables both LESC and non-OOB legacy. The device only does legacy
       OOB. Niche; mostly a code-size optimization for products that have
       no scanner, no display, and a legacy-only OOB channel.
   * - :kconfig:option:`CONFIG_BT_SMP_LEGACY_PAIR_ONLY`
     - Forces legacy pairing on a device that would otherwise prefer LESC.
       Depends on :kconfig:option:`CONFIG_BT_TESTING`. Only relevant for
       testing legacy paths between two Zephyr devices.
   * - :kconfig:option:`CONFIG_BT_OOB_DATA_FIXED`
     - Pins the LESC OOB ``r`` to a hardcoded value. Testing only, not for
       production. Does not pin the public key, so ``Cb`` still varies
       across boots.
   * - :kconfig:option:`CONFIG_BT_USE_DEBUG_KEYS`
     - Uses the spec-defined debug ECDH keypair. Publicly known. Provides
       no MITM protection. Testing only.

Application APIs:

* :c:func:`bt_le_oob_get_local` returns local OOB information including a
  freshly generated LESC ``(r, Cb)``.
* :c:func:`bt_le_oob_set_sc_data` provides peer LESC OOB data in response
  to an :c:struct:`bt_conn_auth_cb` ``oob_data_request`` callback.
* :c:func:`bt_le_oob_set_legacy_tk` provides the legacy TK in response to
  the same callback.
* :c:func:`bt_le_oob_set_sc_flag` and :c:func:`bt_le_oob_set_legacy_flag`
  control the per-mode OOB-present flag the stack advertises in pairing
  messages. The application is responsible for setting these only when
  matching data is actually available, because of the central-side flag
  asymmetry described above.
