#pragma once

#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/View.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
#include <xrpl/protocol/TxFormats.h>

#include <cstdint>
#include <memory>

namespace xrpl {

/**
 * A proposal is terminal once it can no longer be completed and submitted:
 * its Expiration has passed, or the proposed transaction carries a
 * LastLedgerSequence that the current ledger sequence has passed. A terminal
 * proposal stops accepting signatures and may be cancelled by anyone.
 */
inline bool
isProposalTerminal(ReadView const& view, std::shared_ptr<SLE const> const& sleProposal)
{
    if (hasExpired(view, (*sleProposal)[~sfExpiration]))
        return true;

    auto const raw = sleProposal->getFieldObject(sfRawTransaction);
    return raw.isFieldPresent(sfLastLedgerSequence) &&
        view.seq() > raw.getFieldU32(sfLastLedgerSequence);
}

/**
 * Owner-reserve increments held by a proposal: a proposed Batch stores up to
 * eight inner transactions plus multi-account signatures, so it reserves
 * more than an ordinary proposed transaction.
 */
inline std::uint32_t
proposalOwnerCount(STObject const& proposedTx)
{
    return proposedTx.getFieldU16(sfTransactionType) == ttBATCH ? 10 : 5;
}

}  // namespace xrpl
