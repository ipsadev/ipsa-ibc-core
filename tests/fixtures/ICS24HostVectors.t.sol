pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ICS24Host } from "ibc/utils/ICS24Host.sol";
import { IICS26RouterMsgs } from "ibc/msgs/IICS26RouterMsgs.sol";
import { IICS24HostErrors } from "ibc/errors/IICS24HostErrors.sol";

contract Harness {
    function acknowledgement(bytes[] memory acks) external pure returns (bytes32) {
        return ICS24Host.packetAcknowledgementCommitmentBytes32(acks);
    }
}

contract Vectors is Test {
    function payload(string memory encoding, bytes memory value) internal pure returns (IICS26RouterMsgs.Payload memory) {
        return IICS26RouterMsgs.Payload("transfer", "transfer", "ics20-1", encoding, value);
    }

    function test_print() public {
        IICS26RouterMsgs.Payload[] memory one = new IICS26RouterMsgs.Payload[](1);
        one[0] = payload("application/x-solidity-abi", hex"deadbeef");
        IICS26RouterMsgs.Packet memory single = IICS26RouterMsgs.Packet(7, "sepolia-0", "stellar-testnet-1", 1790301922, one);
        console.log("packet-one-payload", vm.toString(ICS24Host.packetCommitmentBytes32(single)));

        IICS26RouterMsgs.Payload[] memory two = new IICS26RouterMsgs.Payload[](2);
        two[0] = payload("application/json", bytes("{\"denom\":\"native\"}"));
        two[1] = payload("application/x-solidity-abi", hex"");
        IICS26RouterMsgs.Packet memory double = IICS26RouterMsgs.Packet(1, "07-tendermint-9", "08-wasm-1", 0, two);
        console.log("packet-two-payloads", vm.toString(ICS24Host.packetCommitmentBytes32(double)));

        bytes[] memory okAck = new bytes[](1);
        okAck[0] = bytes("ok");
        console.log("ack-one", vm.toString(ICS24Host.packetAcknowledgementCommitmentBytes32(okAck)));

        bytes[] memory twoAcks = new bytes[](2);
        twoAcks[0] = hex"01";
        twoAcks[1] = ICS24Host.UNIVERSAL_ERROR_ACK;
        console.log("ack-two", vm.toString(ICS24Host.packetAcknowledgementCommitmentBytes32(twoAcks)));

        console.log("universal-error-ack", vm.toString(ICS24Host.UNIVERSAL_ERROR_ACK));
        console.log("path-commitment", vm.toString(ICS24Host.packetCommitmentPathCalldata("sepolia-0", 7)));
        console.log("path-receipt", vm.toString(ICS24Host.packetReceiptCommitmentPathCalldata("stellar-testnet-1", 7)));
        console.log("path-acknowledgement", vm.toString(ICS24Host.packetAcknowledgementCommitmentPathCalldata("stellar-testnet-1", 18446744073709551615)));
    }

    function test_an_empty_acknowledgement_list_reverts() public {
        Harness harness = new Harness();
        vm.expectRevert(IICS24HostErrors.NoAcknowledgements.selector);
        harness.acknowledgement(new bytes[](0));
    }
}
