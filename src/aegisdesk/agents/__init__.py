"""Agent layer for the AegisDesk vertical slice.

The agents turn untrusted model output into typed decisions. They never establish identity,
authorization, or approval: those stay with the deterministic control plane (session, guard,
policy, approval store) built in S1-S11. An agent may propose an action; the application
decides whether it executes.
"""
