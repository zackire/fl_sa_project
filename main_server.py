import argparse
import time
import os
import logging
from communication.logger_utils import setup_custom_logger
from communication.mqtt_server_handler import MQTTServerHandler
from secure_aggregation.sa_server_orchestrator import SecureAggregationServer
from fl_baseline.vanillaFL_server import VanillaFLServer
from metrics.metrics_collector import MetricsCollector
from fl_core.model import get_model_dimensions   # ← dynamic dimension probe

from crypto.stacks.stack_a import Stack1Crypto
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

# ─── Default dataset path ─────────────────────────────────────────────────────
DEFAULT_DATA_PATH = os.getenv("DATA_PATH", "/data/Train_Test_Network.csv")


def main():
    parser = argparse.ArgumentParser(description="FL Server Entry Point")
    parser.add_argument("--ip",        type=str, required=True,  help="MQTT Broker IP")
    parser.add_argument("--k",         type=int, required=True,  help="Expected clients (K)")
    parser.add_argument("--t",         type=int, required=True,  help="Threshold (T)")
    parser.add_argument("--stack",     type=str, required=True,  choices=["A", "B", "C"])
    parser.add_argument("--ca",        type=str, required=False)
    parser.add_argument("--cert",      type=str, required=False)
    parser.add_argument("--key",       type=str, required=False)
    parser.add_argument("--data-path", type=str, default=DEFAULT_DATA_PATH,
                        help="Path to Train_Test_Network.csv — used only to probe feature dimensions")
    parser.add_argument("--results-dir", type=str, default="metrics/results/utilities",
                        help="Directory to write metrics CSV files (default: metrics/results/utilities)")
    parser.add_argument("--rounds", type=int, default=None,
                        help="Number of FL rounds to run before shutting down (default: run indefinitely)")
    args = parser.parse_args()

    logger = setup_custom_logger("server")
    mode   = os.getenv("PROTOCOL_MODE", "secagg").lower()

    # ── Dynamically detect model dimensions from the real dataset ─────────────
    # Replaces the old hardcoded MODEL_DIMENSIONS = [(10,), (1,)].
    # Reads only 500 rows so it completes in milliseconds even for large CSVs.
    model_dimensions = get_model_dimensions(args.data_path)
    logger.info(f"[Server] model_dimensions resolved to: {model_dimensions}")

    # ── Metrics collector ────────────────────────────────────────────────────
    if mode == "baseline":
        collector = MetricsCollector(
            protocol="baseline",
            stack="",
            role="server",
            node_id="server",
            output_dir=args.results_dir,
        )
    else:
        collector = MetricsCollector(
            protocol="secagg",
            stack=f"stack{args.stack.upper()}",
            role="server",
            node_id="server",
            output_dir=args.results_dir,
        )

    # ── MQTT handler ─────────────────────────────────────────────────────────
    mqtt_handler = MQTTServerHandler(
        broker_ip=args.ip,
        port=8883,
        ca_path=args.ca,
        cert_path=args.cert,
        key_path=args.key,
    )

    # ── Orchestrator ─────────────────────────────────────────────────────────
    if mode == "baseline":
        logger.info("--- SERVER BOOTING IN VANILLA FL MODE ---")
        orchestrator = VanillaFLServer(
            mqtt_handler=mqtt_handler,
            expected_k=args.k,
            metrics=collector,
        )
    else:
        logger.info(f"--- SERVER BOOTING IN SECURE AGGREGATION MODE (STACK {args.stack}) ---")
        logger.info(f"    model_dimensions : {model_dimensions}")
        logger.info(f"    expected_k       : {args.k}  |  t_threshold: {args.t}")

        if args.stack == "A":
            crypto_stack = Stack1Crypto("server")
        elif args.stack == "B":
            crypto_stack = Stack2Crypto("server")
        else:
            crypto_stack = Stack3Crypto("server")

        orchestrator = SecureAggregationServer(
            mqtt_handler=mqtt_handler,
            t_threshold=args.t,
            expected_k=args.k,
            crypto_stack=crypto_stack,
            model_dimensions=model_dimensions,   # ← real dimensions, not [(10,),(1,)]
            metrics=collector,
        )

    mqtt_handler.set_orchestrator(orchestrator)
    mqtt_handler.start()

    # Signal the orchestrator about the desired round limit
    orchestrator.set_round_limit(args.rounds)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        collector.print_summary()
        mqtt_handler.stop()


if __name__ == "__main__":
    main()