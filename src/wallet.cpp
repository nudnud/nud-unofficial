// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 The NUD developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "coincontrol.h"
#include <boost/algorithm/string/replace.hpp>

using namespace std;


bool bSpendZeroConfChange = true;

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const pair<int64, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

bool GetSenderBindKey(CKeyID& key, CTransaction const& tx);

static bool GetBoundAddress(
    CWallet* wallet,
    uint160 const& hash,
    CNetAddr& address
) {
    std::set<
        std::pair<CNetAddr, uint64>
    > const& address_binds = wallet->get_address_binds();
    for (
        std::set<
            std::pair<CNetAddr, uint64>
        >::const_iterator checking = address_binds.begin();
        address_binds.end() != checking;
        checking++
    ) {
        if (
            hash == Hash160(
                CreateAddressIdentification(
                    checking->first,
                    checking->second
                )
            )
        ) {
            address = checking->first;
            return true;
        }
    }
    return false;
}

static bool ConfirmedTransactionSubmit(
    CTransaction sent_tx,
    CTransaction& confirming_tx
) {
    uint256 const tx_hash = sent_tx.GetHash();
    CValidationState state;
    if (!sent_tx.AcceptToMemoryPool(state, true, false)) {
        return false;
    }
    SyncWithWallets(tx_hash, sent_tx, NULL, true);
    RelayTransaction(sent_tx, tx_hash);

    CTransaction confirmTx;

    CTxOut confirm_transfer;

    confirm_transfer.scriptPubKey = CScript() << tx_hash;

    confirmTx.vout.push_back(confirm_transfer);

    confirming_tx = confirmTx;
    return true;
}

static bool ProcessOffChain(
    CWallet* wallet,
    std::string const& name,
    CTransaction const& tx,
    int64 timeout
) {
    if (
        "request-delegate" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        uint64 join_nonce;
        CNetAddr address;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(join_nonce) > data.size()) {
                return false;
            }
            memcpy(&join_nonce, data.data(), sizeof(join_nonce));
        } else {
            return false;
        }
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            std::vector<unsigned char> const unique(
                data.begin() + 6,
                data.end()
            );
            if (
                !address.SetSpecial(
                    EncodeBase32(unique.data(), unique.size()) + ".onion"
                )
            ) {
                return false;
            }
        } else {
            return false;
        }
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            CTransaction confirmTx;

            CTxOut confirm_transfer;

            uint64 const nonce = GetRand(std::numeric_limits<uint64>::max());

            wallet->store_address_bind(address, nonce);

            confirm_transfer.scriptPubKey = CScript() << data << nonce;

            confirmTx.vout.push_back(confirm_transfer);

            PushOffChain(address, "confirm-delegate", confirmTx);

            CNetAddr const local = GetLocalTorAddress(address);

            std::vector<
                unsigned char
            > const key = wallet->store_delegate_attempt(
                true,
                local,
                address,
                CScript(position, payload.end()),
                payload_output.nValue
            );

            wallet->store_join_nonce_delegate(join_nonce, key);

            CTransaction delegate_identification_request;

            CTxOut request_transfer;
            request_transfer.scriptPubKey = CScript() << data << key;

            delegate_identification_request.vout.push_back(request_transfer);

            PushOffChain(
                address,
                "request-delegate-identification",
                delegate_identification_request
            );

            return true;
        } else {
            return false;
        }
    } else if (
        "confirm-delegate" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> delegate_key;
        std::vector<unsigned char> data;
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            delegate_key = data;
        } else {
            return false;
        }
        if (!wallet->get_delegate_attempt(delegate_key, delegate_data)) {
            return false;
        }
        if (delegate_data.first) {
            return false;
        }
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            uint64 nonce;
            if (sizeof(nonce) > data.size()) {
                return false;
            }
            memcpy(&nonce, data.data(), sizeof(nonce));
            InitializeSenderBind(
                delegate_key,
                nonce,
                delegate_data.second.first.first,
                delegate_data.second.first.second,
                delegate_data.second.second.second
            );
            wallet->store_delegate_nonce(
                nonce,
                delegate_key
            );
            return true;
        } else {
            return false;
        }
    } else if (
        "confirm-sender" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> delegate_key;
        std::vector<unsigned char> data;
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            delegate_key = data;
        } else {
            return false;
        }
        if (!wallet->get_delegate_attempt(delegate_key, delegate_data)) {
            return false;
        }
        if (!delegate_data.first) {
            return false;
        }
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            uint64 nonce;
            if (sizeof(nonce) > data.size()) {
                return false;
            }
            memcpy(&nonce, data.data(), sizeof(nonce));
            InitializeDelegateBind(
                delegate_key,
                nonce,
                delegate_data.second.first.first,
                delegate_data.second.first.second,
                delegate_data.second.second.second
            );
            wallet->store_delegate_nonce(
                nonce,
                delegate_key
            );
            return true;
        } else {
            return false;
        }
    } else if (
        "to-delegate" == name
    ) {
        uint160 hash;
        if (!GetSenderBindHash(hash, tx)) {
            return false;
        }
        CNetAddr bound;
        if (
            !GetBoundAddress(
                wallet,
                hash,
                bound
            )
        ) {
            return false;
        }
        CTransaction signed_tx = tx;
        CPubKey signing_key;

        do {
            CReserveKey reserve_key(wallet);
            if (!reserve_key.GetReservedKey(signing_key)) {
                throw std::runtime_error("could not find signing address");
            }
        } while (false);

        CBitcoinAddress signing_address;

        signing_address.Set(signing_key.GetID());

        SignSenderBind(wallet, signed_tx, signing_address);

        PushOffChain(
            bound,
            "request-sender-funding",
            signed_tx
        );
        return true;
    } else if (
        "to-sender" == name
    ) {
        uint160 hash;
        if (!GetDelegateBindHash(hash, tx)) {
            return false;
        }
        CNetAddr bound;
        if (
            !GetBoundAddress(
                wallet,
                hash,
                bound
            )
        ) {
            return false;
        }
        CTransaction signed_tx = tx;
        CPubKey signing_key;

        do {
            CReserveKey reserve_key(wallet);
            if (!reserve_key.GetReservedKey(signing_key)) {
                throw std::runtime_error("could not find signing address");
            }
        } while (false);

        CBitcoinAddress signing_address;

        signing_address.Set(signing_key.GetID());

        SignDelegateBind(wallet, signed_tx, signing_address);

        PushOffChain(
            bound,
            "request-delegate-funding",
            signed_tx
        );
        return true;
    } else if (
        "request-sender-funding" == name
    ) {
        uint160 hash;
        if (!GetSenderBindHash(hash, tx)) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_hash_delegate(hash, key)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (delegate_data.first) {
            return false;
        }
        CKeyID signing_key;
        if (!GetSenderBindKey(signing_key, tx)) {
            return false;
        }
        CTxDestination const delegate_destination(signing_key);
        CScript payment_script;
        payment_script.SetDestination(delegate_destination);
        if (!wallet->set_delegate_destination(key, payment_script)) {
            return false;
        }
        CTransaction const funded_tx = FundAddressBind(wallet, tx);
        PushOffChain(
            delegate_data.second.first.second,
            "funded-sender-bind",
            funded_tx
        );
        return true;
    } else if (
        "request-delegate-funding" == name
    ) {
        uint160 hash;
        if (!GetDelegateBindHash(hash, tx)) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_hash_delegate(hash, key)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (!delegate_data.first) {
            return false;
        }
        CTransaction const funded_tx = FundAddressBind(wallet, tx);
        PushOffChain(
            delegate_data.second.first.second,
            "funded-delegate-bind",
            funded_tx
        );
        return true;
    } else if (
        "finalized-transfer" == name
    ) {
        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(tx, confirmTx)) {
            return false;
        }

        return true;
    } else if (
        "funded-delegate-bind" == name
    ) {
        uint160 hash;
        if (!GetDelegateBindHash(hash, tx)) {
            return false;
        }
        CNetAddr bound;
        if (
            !GetBoundAddress(
                wallet,
                hash,
                bound
            )
        ) {
            return false;
        }
        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(tx, confirmTx)) {
            return false;
        }

        PushOffChain(bound, "confirm-delegate-bind", confirmTx);

        return true;
    } else if (
        "funded-sender-bind" == name
    ) {
        uint160 hash;
        if (!GetSenderBindHash(hash, tx)) {
            return false;
        }
        CNetAddr bound;
        if (
            !GetBoundAddress(
                wallet,
                hash,
                bound
            )
        ) {
            return false;
        }
        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(tx, confirmTx)) {
            return false;
        }

        PushOffChain(bound, "confirm-sender-bind", confirmTx);

        return true;
    } else if (
        "confirm-transfer" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        uint256 transfer_txid;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(transfer_txid) > data.size()) {
                return false;
            }
            memcpy(&transfer_txid, data.data(), sizeof(transfer_txid));
        } else {
            return false;
        }
        uint256 hashBlock = 0;
        CTransaction transfer_tx;
        if (!GetTransaction(transfer_txid, transfer_tx, hashBlock, true)) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (0 == hashBlock) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (transfer_tx.vin.empty()) {
            return false;
        }
        CTransaction prevTx;
        if (
            !GetTransaction(
                transfer_tx.vin[0].prevout.hash,
                prevTx,
                hashBlock,
                true
            )
        ) {
            return false;
        }
        if (0 == hashBlock) {
            return false;
        }
        uint160 hash;
        if (!GetDelegateBindHash(hash, prevTx)) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_hash_delegate(hash, key)) {
            return false;
        }
        CKeyID signing_key;
        if (!GetDelegateBindKey(signing_key, prevTx)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (!delegate_data.first) {
            return false;
        }

        return true;
    } else if (
        "committed-transfer" == name
    ) {
        CTransaction signed_tx = tx;
        if (signed_tx.vout.empty()) {
            return false;
        }
        CTxOut& payload_output = signed_tx.vout[0];
        CScript& payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        uint64 join_nonce;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(join_nonce) > data.size()) {
                return false;
            }
            memcpy(&join_nonce, data.data(), sizeof(join_nonce));
        } else {
            return false;
        }
        payload = CScript(position, payload.end());

        if (signed_tx.vin.empty()) {
            return false;
        }
        CTransaction prevTx;
        uint256 hashBlock = 0;
        if (
            !GetTransaction(
                signed_tx.vin[0].prevout.hash,
                prevTx,
                hashBlock,
                true
            )
        ) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (0 == hashBlock) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        uint160 hash;
        if (!GetDelegateBindHash(hash, prevTx)) {
            return false;
        }
        CNetAddr bound;
        if (
            !GetBoundAddress(
                wallet,
                hash,
                bound
            )
        ) {
            return false;
        }
        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(signed_tx, confirmTx)) {
            return false;
        }

        PushOffChain(bound, "confirm-transfer", confirmTx);

        if (confirmTx.vout.empty()) {
            return false;
        }
        CTxOut const confirm_payload_output = confirmTx.vout[0];
        CScript const confirm_payload = confirm_payload_output.scriptPubKey;
        uint256 transfer_txid;
        position = confirm_payload.begin();
        if (position >= confirm_payload.end()) {
            return false;
        }
        if (!confirm_payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(transfer_txid) > data.size()) {
                return false;
            }
            memcpy(&transfer_txid, data.data(), sizeof(transfer_txid));
        } else {
            return false;
        }
        CTransaction transfer_tx;
        if (!GetTransaction(transfer_txid, transfer_tx, hashBlock, true)) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (0 == hashBlock) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (transfer_tx.vin.empty()) {
            return false;
        }
        if (
            !GetTransaction(
                transfer_tx.vin[0].prevout.hash,
                prevTx,
                hashBlock,
                true
            )
        ) {
            return false;
        }
        if (0 == hashBlock) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_join_nonce_delegate(join_nonce, key)) {
            return false;
        }
        CKeyID signing_key;
        if (!GetDelegateBindKey(signing_key, prevTx)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (delegate_data.first) {
            return false;
        }
        uint256 bind_tx;
        if (!wallet->get_sender_bind(key, bind_tx)) {
            return false;
        }
        CTransaction const finalization_tx = CreateTransferFinalize(
            wallet,
            bind_tx,
            delegate_data.second.second.first
        );

        PushOffChain(
            delegate_data.second.first.second,
            "finalized-transfer",
            finalization_tx
        );

        return true;
    } else if (
        "confirm-sender-bind" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        uint256 bind_tx;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(bind_tx) > data.size()) {
                return false;
            }
            memcpy(&bind_tx, data.data(), sizeof(bind_tx));
        } else {
            return false;
        }
        CTransaction prevTx;
        uint256 hashBlock = 0;
        if (!GetTransaction(bind_tx, prevTx, hashBlock, true)) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (0 == hashBlock) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        uint160 hash;
        if (!GetSenderBindHash(hash, prevTx)) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_hash_delegate(hash, key)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (delegate_data.first) {
            return false;
        }
        wallet->set_sender_bind(key, bind_tx);
        return true;
    } else if (
        "confirm-delegate-bind" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        uint256 bind_tx;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(bind_tx) > data.size()) {
                return false;
            }
            memcpy(&bind_tx, data.data(), sizeof(bind_tx));
        } else {
            return false;
        }
        CTransaction prevTx;
        uint256 hashBlock = 0;
        if (!GetTransaction(bind_tx, prevTx, hashBlock, true)) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        if (0 == hashBlock) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        uint160 hash;
        if (!GetDelegateBindHash(hash, prevTx)) {
            return false;
        }
        std::vector<unsigned char> key;
        if (!wallet->get_hash_delegate(hash, key)) {
            return false;
        }
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        > delegate_data;
        if (!wallet->get_delegate_attempt(key, delegate_data)) {
            return false;
        }
        if (!delegate_data.first) {
            return false;
        }
        uint64 bind_nonce;
        if (!wallet->get_delegate_nonce(bind_nonce, key)) {
            return false;
        }
        uint64 const transfer_nonce = GetRand(
            std::numeric_limits<uint64>::max()
        );
        CTransaction commit_tx = CreateTransferCommit(
            wallet,
            bind_tx,
            delegate_data.second.first.first,
            bind_nonce,
            transfer_nonce,
            delegate_data.second.second.first
        );
        uint64 join_nonce;
        if (!wallet->get_delegate_join_nonce(key, join_nonce)) {
            return false;
        }
        if (commit_tx.vout.empty()) {
            return false;
        }
        commit_tx.vout[0].scriptPubKey = (
            CScript() << join_nonce
        ) + commit_tx.vout[0].scriptPubKey;
        PushOffChain(
            delegate_data.second.first.second,
            "committed-transfer",
            commit_tx
        );
        return true;
    } else if (
        "request-delegate-identification" == name
    ) {
        if (tx.vout.empty()) {
            return false;
        }
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;
        CNetAddr address;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            std::pair<
                bool,
                std::pair<
                    std::pair<CNetAddr, CNetAddr>,
                    std::pair<CScript, uint64>
                >
            > delegate_data;
            if (!wallet->get_delegate_attempt(data, delegate_data)) {
                return false;
            }
            if (delegate_data.first) {
                return false;
            }
            address = delegate_data.second.first.second;
        } else {
            return false;
        }
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            CTransaction confirmTx;

            CTxOut confirm_transfer;

            uint64 const nonce = GetRand(std::numeric_limits<uint64>::max());

            wallet->store_address_bind(address, nonce);

            confirm_transfer.scriptPubKey = CScript() << data << nonce;

            confirmTx.vout.push_back(confirm_transfer);

            PushOffChain(address, "confirm-sender", confirmTx);

            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

CTransaction FundAddressBind(CWallet* wallet, CTransaction unfundedTx) {
    CWalletTx fundedTx;

    string failure_reason;

    CReserveKey reserve_key(wallet);

    int64 fee = 0;

    CCoinControl coin_control;

    vector<pair<CScript, int64> > send_vector;

    for (
        vector<CTxOut>::iterator output = unfundedTx.vout.begin();
        unfundedTx.vout.end() != output;
        output++
    ) {
        send_vector.push_back(
            std::make_pair(output->scriptPubKey, output->nValue)
        );
    }

    if (
        !wallet->CreateTransaction(
            send_vector,
            fundedTx,
            reserve_key,
            fee,
            failure_reason,
            &coin_control
        )
    ) {
        throw runtime_error("fundaddressbind error: " + failure_reason);
    }

    return fundedTx;
}

CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey, secret.GetPrivKey());
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::push_off_chain_transaction(
    std::string const& name,
    CTransaction const& tx
) {
    LOCK(cs_wallet);
    if (GetBoolArg("-processoffchain", true)) {
        if (ProcessOffChain(this, name, tx, GetTime() + 6000)) {
            return true;
        }
    }
    off_chain_transactions.push_back(std::make_pair(name, tx));
    return true;
}

bool CWallet::pop_off_chain_transaction(std::string& name, CTransaction& tx) {
    LOCK(cs_wallet);
    if (off_chain_transactions.empty()) {
        return false;
    }
    name = off_chain_transactions.front().first;
    tx = off_chain_transactions.front().second;
    off_chain_transactions.pop_front();
    return true;
}

void CWallet::push_deferred_off_chain_transaction(
    int64 timeout,
    std::string const& name,
    CTransaction const& tx
) {
    LOCK(cs_wallet);
    deferred_off_chain_transactions.push_back(
        std::make_pair(timeout, std::make_pair(name, tx))
    );
}

void CWallet::reprocess_deferred_off_chain_transactions() {
    LOCK(cs_wallet);
    std::list<
        std::pair<int64, std::pair<std::string, CTransaction> >
    > work_copy;
    work_copy.swap(
        deferred_off_chain_transactions
    );
    int64 const now = GetTime();
    for (
        std::list<
            std::pair<int64, std::pair<std::string, CTransaction> >
        >::const_iterator processing = work_copy.begin();
        work_copy.end() != processing;
        processing++
    ) {
        if (now >= processing->first) {
            off_chain_transactions.push_back(
                std::make_pair(
                    processing->second.first,
                    processing->second.second
                )
            );
        } else if (
            !ProcessOffChain(
                this,
                processing->second.first,
                processing->second.second,
                processing->first
            )
        ) {
            off_chain_transactions.push_back(
                std::make_pair(
                    processing->second.first,
                    processing->second.second
                )
            );
        }
    }
}

void CWallet::store_join_nonce_delegate(
    uint64 const& join_nonce,
    std::vector<unsigned char> const& key
) {
    join_nonce_delegates[join_nonce] = key;
}

bool CWallet::get_delegate_join_nonce(
    std::vector<unsigned char> const& key,
    uint64& join_nonce
) {
    for (
        std::map<
            uint64,
            std::vector<unsigned char>
        >::const_iterator checking = join_nonce_delegates.begin();
        join_nonce_delegates.end() != checking;
        checking++
    ) {
        if (key == checking->second) {
            join_nonce = checking->first;
            return true;
        }
    }
    return false;
}

bool CWallet::get_join_nonce_delegate(
    uint64 const& join_nonce,
    std::vector<unsigned char>& key
) {
    if (join_nonce_delegates.end() == join_nonce_delegates.find(join_nonce)) {
        return false;
    }
    key = join_nonce_delegates.at(join_nonce);
    return true;
}

void CWallet::store_address_bind(CNetAddr const& address, uint64 const& nonce) {
    address_binds.insert(std::make_pair(address, nonce));
}

std::set<std::pair<CNetAddr, uint64> >& CWallet::get_address_binds() {
    return address_binds;
}

void CWallet::store_hash_delegate(
    uint160 const& hash,
    std::vector<unsigned char> const& key
) {
    hash_delegates[hash] = key;
}

bool CWallet::get_hash_delegate(
    uint160 const& hash,
    std::vector<unsigned char>& key 
) {
    if (hash_delegates.end() == hash_delegates.find(hash)) {
        return false;
    }
    key = hash_delegates.at(hash);
    return true;
}

void CWallet::set_sender_bind(
    std::vector<unsigned char> const& key,
    uint256 const& bind_tx
) {
    sender_binds[key] = bind_tx;
}
    
bool CWallet::get_sender_bind(
    std::vector<unsigned char> const& key,
    uint256& bind_tx
) {
    if (sender_binds.end() == sender_binds.find(key)) {
        return false;
    }
    bind_tx = sender_binds.at(key);
    return true;
}

void CWallet::store_delegate_nonce(
    uint64 const& nonce,
    std::vector<unsigned char> const& key
) {
    delegate_nonces[key] = nonce;
}

bool CWallet::get_delegate_nonce(
    uint64& nonce,
    std::vector<unsigned char> const& key
) {
    if (delegate_nonces.end() == delegate_nonces.find(key)) {
        return false;
    }
    nonce = delegate_nonces.at(key);
    return true;
}

std::vector<unsigned char> CWallet::store_delegate_attempt(
    bool is_delegate,
    CNetAddr const& self,
    CNetAddr const& other,
    CScript const& destination,
    uint64 const& amount
) {
    std::vector<unsigned char> key(sizeof(uint64));
    do {
        uint64 const numeric = GetRand(std::numeric_limits<uint64>::max());
        memcpy(key.data(), &numeric, sizeof(numeric));
        if (delegate_attempts.end() == delegate_attempts.find(key)) {
            break;
        }
    } while (true);
    delegate_attempts[key] = std::make_pair(
        is_delegate,
        std::make_pair(
            std::make_pair(self, other),
            std::make_pair(destination, amount)
        )
    );
    return key;
}

bool CWallet::set_delegate_destination(
    std::vector<unsigned char> const& key,
    CScript const& destination
) {
    std::map<
        std::vector<unsigned char>,
        std::pair<
            bool,
            std::pair<
                std::pair<CNetAddr, CNetAddr>,
                std::pair<CScript, uint64>
            >
        >
    >::iterator found = delegate_attempts.find(key);
    if (delegate_attempts.end() == found) {
        return false;
    }
    found->second.second.second.first = destination;
    return true;
}

bool CWallet::get_delegate_attempt(
    std::vector<unsigned char> const& key,
    std::pair<
        bool,
        std::pair<
            std::pair<CNetAddr, CNetAddr>,
            std::pair<CScript, uint64>
        >
    >& data
) {
    if (delegate_attempts.end() == delegate_attempts.find(key)) {
        return false;
    }
    data = delegate_attempts.at(key);
    return true;
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64 CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    int64 nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.n >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    printf("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                }
            }
        }
    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    unsigned int latestNow = wtx.nTimeReceived;
                    unsigned int latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64 latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64 nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    unsigned int& blocktime = mapBlockIndex[wtxIn.hashBlock]->nTime;
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        if (vchDefaultKey.IsValid()) {
            CScript scriptDefaultKey;
            scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            {
                if (txout.scriptPubKey == scriptDefaultKey)
                {
                    CPubKey newDefaultKey;
                    if (GetKeyFromPool(newDefaultKey, false))
                    {
                        SetDefaultKey(newDefaultKey);
                        SetAddressBookName(vchDefaultKey.GetID(), "");
                    }
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx);

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this,tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(pblock);
            return AddToWallet(wtx);
        }
        else
            WalletUpdateSpent(tx);
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

int64 CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    txnouttype tx_type;
    vector<vector<unsigned char> > values;

    if (Solver(txout.scriptPubKey, tx_type, values)) {
        switch (tx_type) {
        case TX_ESCROW_FEE:
        case TX_ESCROW_SENDER:
        case TX_ESCROW:
            return false;
        }
    }

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64 CWalletTx::GetTxTime() const
{
    int64 n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64> >& listReceived,
                           list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    int64 nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64 nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        bool fIsMine;
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
            fIsMine = pwallet->IsMine(txout);
        }
        else if (!(fIsMine = pwallet->IsMine(txout)))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                   this->GetHash().ToString().c_str());
            address = CNoDestination();
        }

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(make_pair(address, txout.nValue));

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine)
            listReceived.push_back(make_pair(address, txout.nValue));
    }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64& nReceived,
                                  int64& nSent, int64& nFee) const
{
    nReceived = nSent = nFee = 0;

    int64 allFee;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions()
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else
                {
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx.GetHash(), tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK(cs_wallet);
        fRepeat = false;
        bool fMissing = false;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (wtx.IsCoinBase() && wtx.IsSpent(0))
                continue;

            CCoins coins;
            bool fUpdated = false;
            bool fFound = pcoinsTip->GetCoins(wtx.GetHash(), coins);
            if (fFound || wtx.GetDepthInMainChain() > 0)
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                for (unsigned int i = 0; i < wtx.vout.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if ((i >= coins.vout.size() || coins.vout[i].IsNull()) && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        fMissing = true;
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!wtx.IsCoinBase())
                    wtx.AcceptWalletTransaction(false);
            }
        }
        if (fMissing)
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        // Important: versions of bitcoin before 0.8.6 had a bug that inserted
        // empty transactions into the vtxPrev, which will cause the node to be
        // banned when retransmitted, hence the check for !tx.vin.empty()
        if (!tx.IsCoinBase() && !tx.vin.empty())
            if (tx.GetDepthInMainChain() == 0)
                RelayTransaction((CTransaction)tx, tx.GetHash());
    }
    if (!IsCoinBase())
    {
        if (GetDepthInMainChain() == 0) {
            uint256 hash = GetHash();
            printf("Relaying wtx %s\n", hash.ToString().c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWallet::ResendWalletTransactions()
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    static int64 nNextTime;
    if (GetTime() < nNextTime)
        return;
    bool fFirst = (nNextTime == 0);
    nNextTime = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    static int64 nLastTime;
    if (nTimeBestReceived < nLastTime)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction();
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CWallet::GetBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64 CWallet::GetUnconfirmedBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64 CWallet::GetImmatureBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) &&
                    !IsLockedCoin((*it).first, i) && pcoin->vout[i].nValue >= nMinimumInputValue &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i))) 
                    vCoins.push_back(COutput(pcoin, i, nDepth));
            }
        }
    }
}

static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
                                  vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins,
                                 set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
    int64 nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        int64 n = pcoin->vout[i].nValue;

        pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64 nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        //// debug print
        printf("SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                printf("%s ", FormatMoney(vValue[i].first).c_str());
        printf("total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
}

bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);
    
    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected())
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet)));
}




bool CWallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend,
                                CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl)
{
    int64 nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
    {
        if (nValue < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.BindWallet(this);

    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64 nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
                {
                    CTxOut txout(s.second, s.first);
                    if (txout.IsDust())
                    {
                        strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    wtxNew.vout.push_back(txout);
                }

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64 nValueIn = 0;
                if (!SelectCoins(nTotalValue, setCoins, nValueIn, coinControl))
                {
                    strFailReason = _("Insufficient funds");
                    return false;
                }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The priority after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    dPriority += (double)nCredit * (pcoin.first->GetDepthInMainChain()+1);
                }

                int64 nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least nMinTxFee
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < CTransaction::nMinTxFee && nChange > 0 && nChange < CENT)
                {
                    int64 nMoveToFee = min(nChange, CTransaction::nMinTxFee - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;
                    
                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange.SetDestination(coinControl->destChange);
                        
                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked

                        scriptChange.SetDestination(vchPubKey.GetID());
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust())
                    {
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        // Insert change txn at random position:
                        vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size()+1);
                        wtxNew.vout.insert(position, newTxOut);
                    }
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_STANDARD_TX_SIZE)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority /= nBytes;

                // Check that enough fee is included
                int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
                bool fAllowFree = CTransaction::AllowFree(dPriority);
                int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree, GMF_SEND);
                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions();
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64 nValue,
                                CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, coinControl);
}

// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    {
        LOCK2(cs_main, cs_wallet);
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool(true, false))
        {
            // This must not fail. The transaction has already been signed and recorded.
            printf("CommitTransaction() : Error: Transaction not valid");
            return false;
        }
        wtxNew.RelayWalletTransaction();
    }
    return true;
}




string CWallet::SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    string strError;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError))
    {
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"), FormatMoney(nFeeRequired).c_str());
        printf("SendMoney() : %s\n", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}




DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %"PRI64d"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64 nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64 nKeys = max(GetArg("-keypool", 100), (int64)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64 nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %"PRI64d" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool()
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize = max(GetArg("-keypool", 100), 0LL);
        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64 nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %"PRI64d", size=%"PRIszu"\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        printf("keypool reserve %"PRI64d"\n", nIndex);
    }
}

int64 CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64 nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64 nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    printf("keypool keep %"PRI64d"\n", nIndex);
}

void CWallet::ReturnKey(int64 nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    printf("keypool return %"PRI64d"\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64 nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64 CWallet::GetOldestKeyPoolTime()
{
    int64 nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe() ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64 n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               BOOST_FOREACH(CTxOut txout, pcoin->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            if (pwallet->vchDefaultKey.IsValid()) {
                printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
                vchPubKey = pwallet->vchDefaultKey;
            } else
                return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

bool SendByDelegate(
    CWallet* wallet,
    CBitcoinAddress const& address,
    uint64 const& nAmount,
    CAddress& sufficient
) {
    CScript address_script;

    address_script.SetDestination(address.Get());

    std::map<CAddress, uint64> advertised_balances = ListAdvertisedBalances();

    bool found = false;

    for (
        std::map<
            CAddress,
            uint64
        >::const_iterator address = advertised_balances.begin();
        advertised_balances.end() != address;
        address++
    ) {
        if (nAmount <= address->second) {
            found = true;
            sufficient = address->first;
            break;
        }
    }

    if (!found) {
        return false;
    }

    CNetAddr const local = GetLocalTorAddress(sufficient);

    vector<unsigned char> identification(16);

    for (
        int filling = 0;
        16 > filling;
        filling++
    ) {
        identification[filling] = local.GetByte(15 - filling);
    }

    uint64 const join_nonce = GetRand(std::numeric_limits<uint64>::max());

    std::vector<unsigned char> const key = wallet->store_delegate_attempt(
        false,
        local,
        sufficient,
        address_script,
        nAmount
    );

    wallet->store_join_nonce_delegate(join_nonce, key);

    CTransaction rawTx;

    CTxOut transfer;
    transfer.scriptPubKey = CScript() << join_nonce << identification << key;
    transfer.scriptPubKey += address_script;
    transfer.nValue = nAmount;

    rawTx.vout.push_back(transfer);

    PushOffChain(sufficient, "request-delegate", rawTx);

    return true;
}

void SignDelegateBind(
    CWallet* wallet,
    CTransaction& mergedTx,
    CBitcoinAddress const& address
) {
    for (
        vector<CTxOut>::iterator output = mergedTx.vout.begin();
        mergedTx.vout.end() != output;
        output++
    ) {
        bool at_data = false;
        CScript with_signature;
        opcodetype opcode; 
        std::vector<unsigned char> vch;
        CScript::const_iterator pc = output->scriptPubKey.begin();
        while (pc < output->scriptPubKey.end())
        {
            if (!output->scriptPubKey.GetOp(pc, opcode, vch))
            {
                throw runtime_error("error parsing script");
            }
            if (0 <= opcode && opcode <= OP_PUSHDATA4) {
                with_signature << vch;
                if (at_data) {
                    at_data = false;
                    with_signature << OP_DUP;
                    uint256 hash = Hash(vch.begin(), vch.end());

                    if (
                        !Sign1(
                            boost::get<CKeyID>(address.Get()), 
                            *wallet,
                            hash,
                            SIGHASH_ALL,
                            with_signature
                        )
                    ) {
                        throw runtime_error("data signing failed");
                    }

                    CPubKey public_key;
                    wallet->GetPubKey(
                        boost::get<CKeyID>(address.Get()),
                        public_key
                    );
                    with_signature << public_key;
                    with_signature << OP_CHECKDATASIG << OP_VERIFY;
                    with_signature << OP_SWAP << OP_HASH160 << OP_EQUAL;
                    with_signature << OP_VERIFY;
                }
            }
            else {
                with_signature << opcode;
                if (OP_IF == opcode) {
                    at_data = true;
                }
            }
        }
        output->scriptPubKey = with_signature;
    } 
}

void SignSenderBind(
    CWallet* wallet,
    CTransaction& mergedTx,
    CBitcoinAddress const& address
) {
    for (
        vector<CTxOut>::iterator output = mergedTx.vout.begin();
        mergedTx.vout.end() != output;
        output++
    ) {
        int at_data = 0;
        CScript with_signature;
        opcodetype opcode; 
        std::vector<unsigned char> vch;
        CScript::const_iterator pc = output->scriptPubKey.begin();
        while (pc < output->scriptPubKey.end())
        {
            if (!output->scriptPubKey.GetOp(pc, opcode, vch))
            {
                throw runtime_error("error parsing script");
            }
            if (0 <= opcode && opcode <= OP_PUSHDATA4) {
                with_signature << vch;
                if (2 == at_data) {
                    at_data = 0;
                    with_signature << OP_DUP;
                    uint256 hash = Hash(vch.begin(), vch.end());

                    if (!Sign1(boost::get<CKeyID>(address.Get()), *wallet, hash, SIGHASH_ALL, with_signature)) {
                        throw runtime_error("data signing failed");
                    }

                    CPubKey public_key;
                    wallet->GetPubKey(boost::get<CKeyID>(address.Get()), public_key);
                    with_signature << public_key;
                    with_signature << OP_CHECKDATASIG << OP_VERIFY;
                    with_signature << OP_SWAP << OP_HASH160 << OP_EQUAL;
                    with_signature << OP_VERIFY;
                }
            }
            else {
                with_signature << opcode;
                if (OP_IF == opcode) {
                    at_data++;
                } else {
                    at_data = 0;
                }
            }
        }
        output->scriptPubKey = with_signature;
    }
}

CTransaction CreateTransferFinalize(
    CWallet* wallet,
    uint256 const& bind_tx,
    CScript const& destination
) {
    CTransaction prevTx;
    uint256 hashBlock = 0;
    if (!GetTransaction(bind_tx, prevTx, hashBlock, true)) {
        throw runtime_error("transaction unknown");
    }
    int output_index = 0;

    list<
        pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
    > found;
    uint64_t value = 0;

    for (
        vector<CTxOut>::const_iterator checking = prevTx.vout.begin();
        prevTx.vout.end() != checking;
        checking++,
        output_index++
    ) {
        txnouttype transaction_type;
        vector<vector<unsigned char> > values;
        if (!Solver(checking->scriptPubKey, transaction_type, values)) {
            throw std::runtime_error(
                "Unknown script " + checking->scriptPubKey.ToString()
            );
        }
        if (TX_ESCROW_SENDER == transaction_type) {
            found.push_back(
                make_pair(
                    make_pair(output_index, &(*checking)),
                    make_pair(values[4], transaction_type)
                )
            );
            value += checking->nValue;
        }
        if (TX_ESCROW_FEE == transaction_type) {
            found.push_back(
                make_pair(
                    make_pair(output_index, &(*checking)),
                    make_pair(values[1], transaction_type)
                )
            );
            value += checking->nValue;
        }
    }
    if (found.empty()) {
        throw std::runtime_error("invalid bind transaction");
    }

    CTransaction rawTx;

    CTxOut transfer;

    transfer.scriptPubKey = destination;
    transfer.nValue = value;

    rawTx.vout.push_back(transfer);

    list<pair<CTxIn*, int> > inputs;

    rawTx.vin.resize(found.size());

    int input_index = 0;

    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator traversing = found.begin();
        found.end() != traversing;
        traversing++,
        input_index++
    ) {
        CTxIn& input = rawTx.vin[input_index];
        input.prevout = COutPoint(bind_tx, traversing->first.first);
        inputs.push_back(make_pair(&input, input_index));
    }

    list<pair<CTxIn*, int> >::const_iterator input = inputs.begin();

    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator traversing = found.begin();
        found.end() != traversing;
        traversing++,
        input++
    ) {
        uint256 const script_hash = SignatureHash(
            traversing->first.second->scriptPubKey,
            rawTx,
            input->second, 
            SIGHASH_ALL
        );

        CKeyID const keyID = uint160(traversing->second.first);
        if (
            !Sign1(
                keyID,
                *wallet,
                script_hash,
                SIGHASH_ALL,
                input->first->scriptSig
            )
        ) {
            throw std::runtime_error("signing failed");
        }

        CPubKey public_key;
        wallet->GetPubKey(keyID, public_key);
        input->first->scriptSig << public_key;

        if (TX_ESCROW_SENDER == traversing->second.second) {
            input->first->scriptSig << OP_FALSE;
            input->first->scriptSig = (
                CScript() << OP_FALSE
            ) + input->first->scriptSig;
        }

        input->first->scriptSig << OP_TRUE;
    }

    input = inputs.begin();

    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator traversing = found.begin();
        found.end() != traversing;
        traversing++,
        input++
    ) {
        if (
            !VerifyScript(
                input->first->scriptSig,
                traversing->first.second->scriptPubKey,
                rawTx,
                input->second,
                SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                0
            )
        ) {
            throw std::runtime_error("verification failed");
        }
    }

    return rawTx;
}

CTransaction CreateTransferCommit(
    CWallet* wallet,
    uint256 const& bind_tx,
    CNetAddr const& tor_address_parsed,
    boost::uint64_t const& bind_nonce,
    boost::uint64_t const& transfer_nonce,
    CScript const& destination
) {
    vector<unsigned char> identification = CreateAddressIdentification(
        tor_address_parsed,
        bind_nonce
    );

    CTransaction prevTx;
    uint256 hashBlock = 0;
    if (!GetTransaction(bind_tx, prevTx, hashBlock, true)) {
        throw runtime_error("transaction unknown");
    }
    int output_index = 0;
    CTxOut const* found = NULL;
    vector<unsigned char> keyhash;
    for (
        vector<CTxOut>::const_iterator checking = prevTx.vout.begin();
        prevTx.vout.end() != checking;
        checking++,
        output_index++
    ) {
        txnouttype transaction_type;
        vector<vector<unsigned char> > values;
        if (!Solver(checking->scriptPubKey, transaction_type, values)) {
            throw std::runtime_error(
                "Unknown script " + checking->scriptPubKey.ToString()
            );
        }
        if (TX_ESCROW == transaction_type) {
            found = &(*checking);
            keyhash = values[4];
            break;
        }
    }
    if (NULL == found) {
        throw std::runtime_error("invalid bind transaction");
    }

    CTransaction rawTx;

    CTxOut transfer;

    transfer.scriptPubKey = (
        CScript() << transfer_nonce << OP_TOALTSTACK
    ) + destination;
    transfer.nValue = found->nValue;

    rawTx.vout.push_back(transfer);

    rawTx.vin.push_back(CTxIn());

    CTxIn& input = rawTx.vin[0];

    input.prevout = COutPoint(bind_tx, output_index);

    uint256 const script_hash = SignatureHash(
        found->scriptPubKey,
        rawTx,
        0, 
        SIGHASH_ALL
    );

    CKeyID const keyID = uint160(keyhash);
    if (!Sign1(keyID, *wallet, script_hash, SIGHASH_ALL, input.scriptSig)) {
        throw std::runtime_error("signing failed");
    }

    CPubKey public_key;
    wallet->GetPubKey(keyID, public_key);
    input.scriptSig << public_key;

    input.scriptSig << identification;

    input.scriptSig << OP_TRUE;

    if (
        !VerifyScript(
            input.scriptSig,
            found->scriptPubKey,
            rawTx,
            0,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
            0
        )
    ) {
        throw std::runtime_error("verification failed");
    }

    return rawTx;
}

CTransaction CreateDelegateBind(
    CNetAddr const& tor_address_parsed,
    boost::uint64_t const& nonce,
    uint64_t const& transferred,
    boost::uint64_t const& expiry,
    CBitcoinAddress const& recover_address_parsed
) {
    vector<unsigned char> identification = CreateAddressIdentification(
        tor_address_parsed,
        nonce
    );

    CTransaction rawTx;

    CScript data;
    data << OP_IF << Hash160(identification);
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_TOALTSTACK;
    data << OP_DUP << OP_HASH160;
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE << expiry;
    data << OP_CHECKEXPIRY;
    data << OP_ENDIF;

    rawTx.vout.push_back(CTxOut(transferred, data));

    return rawTx;
}

CTransaction CreateSenderBind(
    CNetAddr const& tor_address_parsed,
    boost::uint64_t const& nonce,
    uint64_t const& transferred,
    uint64_t const& fee,
    boost::uint64_t const& expiry,
    CBitcoinAddress const& recover_address_parsed
) {
    vector<unsigned char> identification = CreateAddressIdentification(
        tor_address_parsed,
        nonce
    );

    CTransaction rawTx;

    CScript data;
    data << OP_IF << OP_IF << Hash160(identification) << OP_CHECKTRANSFERNONCE;
    data << OP_ELSE;
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_TOALTSTACK;
    data << OP_DUP << OP_HASH160;
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF << OP_ELSE;
    data << expiry << OP_CHECKEXPIRY; 
    data << OP_ENDIF;

    rawTx.vout.push_back(CTxOut(transferred, data));

    data = CScript();
    data << OP_IF;
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_TOALTSTACK;
    data << OP_DUP << OP_HASH160;
    data << boost::get<CKeyID>(recover_address_parsed.Get());
    data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE << expiry;
    data << OP_CHECKEXPIRY; 
    data << OP_ENDIF;

    rawTx.vout.push_back(CTxOut(fee, data));
    
    return rawTx;
}   

bool GetSenderBindKey(CKeyID& key, CTxOut const& txout) {
    CScript const payload = txout.scriptPubKey;
    txnouttype script_type;
    std::vector<std::vector<unsigned char> > data;
    if (!Solver(payload, script_type, data)) {
        return false;
    }
    if (TX_ESCROW_SENDER != script_type) {
        return false;
    }
    key = CPubKey(data[2]).GetID();
    return true;
}

bool GetSenderBindKey(CKeyID& key, CTransaction const& tx) {
    for (
        std::vector<CTxOut>::const_iterator txout = tx.vout.begin();
        tx.vout.end() != txout;
        txout++
    ) {
        if (GetSenderBindKey(key, *txout)) {
            return true;
        }
    }
    return false;
}

bool GetDelegateBindKey(CKeyID& key, CTxOut const& txout) {
    CScript const payload = txout.scriptPubKey;
    txnouttype script_type;
    std::vector<std::vector<unsigned char> > data;
    if (!Solver(payload, script_type, data)) {
        return false;
    }
    if (TX_ESCROW != script_type) {
        return false;
    }
    key = CPubKey(data[2]).GetID();
    return true;
}

bool GetDelegateBindKey(CKeyID& key, CTransaction const& tx) {
    for (
        std::vector<CTxOut>::const_iterator txout = tx.vout.begin();
        tx.vout.end() != txout;
        txout++
    ) {
        if (GetDelegateBindKey(key, *txout)) {
            return true;
        }
    }
    return false;
}


void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress)
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::LockCoin(COutPoint& output)
{
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint& output)
{
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

