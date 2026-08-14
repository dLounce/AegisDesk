"""Deterministic evaluation harness for AegisDesk.

Executes declarative scenarios through the real control plane and scores task outcome,
trajectory safety, and security metrics from authoritative state. No live model provider,
no durable storage, no benchmarking — those are later milestones. See DESIGN AD-53.
"""
