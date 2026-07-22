#pragma once

#include <xrpl/beast/utility/Journal.h>
#include <xrpl/core/ServiceRegistry.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/ApplyContext.h>
#include <xrpl/tx/Transactor.h>

namespace xrpl {

/**
 * Appends one signature toward a pending TransactionProposal.
 *
 * A contribution is a uniform (SigningFor, SigningPubKey, TxnSignature)
 * triple: SigningFor names the account being authorized, and the ledger
 * derives the rest. The relationship between the submitting Account and
 * SigningFor decides the mode: Account == SigningFor is a single signature
 * that fills the stored transaction's top-level slot; Account != SigningFor
 * is a multi-signature share appended to the relevant Signers array.
 *
 * Scope: this transactor recognizes the proposed transaction's main
 * authorization slot only — its Account, or its Delegate for a delegated
 * transaction. The Counterparty (XLS-66), Sponsor (XLS-68), and Batch
 * participant (XLS-56) slots of the full SigningFor model are deferred; a
 * SigningFor naming any other account fails with tecNO_PERMISSION.
 */
class TransactionProposalSign : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit TransactionProposalSign(ApplyContext& ctx) : Transactor(ctx)
    {
        enforceTransactionInvariants_ = true;
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;

    void
    visitInvariantEntry(bool isDelete, SLE::const_ref before, SLE::const_ref after) override;

    [[nodiscard]] bool
    finalizeInvariants(
        STTx const& tx,
        TER result,
        XRPAmount fee,
        ReadView const& view,
        beast::Journal const& j) override;

private:
    // Invariant state: the before/after images of the proposal this
    // transaction modified, and any proposal entries it touched in another
    // way (there must be none).
    std::shared_ptr<SLE const> proposalBefore_;
    std::shared_ptr<SLE const> proposalAfter_;
    std::size_t modifiedProposals_ = 0;
    std::size_t otherProposalTouches_ = 0;
};

}  // namespace xrpl
