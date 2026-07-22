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
