# Day 11 - HITL Flowchart

```mermaid
flowchart TD
    A[Agent proposal] --> B{High-risk action?}
    B -- Yes --> C[Immediate human approval]
    B -- No --> D{Confidence >= 0.90?}
    D -- Yes --> E[Auto-send]
    D -- No --> F{Confidence >= 0.70?}
    F -- Yes --> G[Queue normal review]
    F -- No --> H[Urgent human escalation]
    C --> I{Fraud anomaly?}
    I -- Yes --> J[Fraud analyst review]
    I -- No --> K[Approve or reject]
    G --> L{Policy evidence conflicts?}
    L -- Yes --> M[Human as tiebreaker]
    L -- No --> K
```

| Decision point | Trigger | HITL model | Reviewer context |
|---|---|---|---|
| High-value transaction | Transfer above 50,000,000 VND or new beneficiary | Human-in-the-loop | Identity, amount, beneficiary, fraud score, recent activity |
| Fraud/account takeover | Unusual device, location, velocity, or failed authentication | Human-on-the-loop | Device history, login geography, timeline, model explanation |
| Policy ambiguity | Medium confidence or conflicting policy evidence | Human-as-tiebreaker | Conversation, policy versions, citations, confidence, proposed response |
