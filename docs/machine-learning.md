# AI-Powered SOC Analyst — Machine Learning

## 1. Overview

Machine Learning is integrated into the AI-Powered SOC Analyst platform as an additional source of evidence during security incident investigation.

The ML layer combines:

- supervised attack classification
- unsupervised anomaly detection
- dataset adaptation
- feature normalization
- model inference
- integration with the LangGraph SOC workflow
- contextual interpretation by the Investigation Agent

The objective is not to let a Machine Learning model make security decisions alone.

Instead, ML results are combined with:

- Wazuh and Suricata evidence
- incident correlation
- Threat Intelligence
- RAG
- LLM reasoning
- MITRE ATT&CK
- Human-in-the-Loop review

---

## 2. ML Architecture

The implemented ML pipeline can be represented as:

```text
Security Event
      |
      v
Feature Extraction
      |
      v
Dataset / Feature Adapter
      |
      +-----------------------+
      |                       |
      v                       v
Supervised Models       Anomaly Detection
      |                       |
      v                       v
Random Forest           Isolation Forest
XGBoost
      |                       |
      +-----------+-----------+
                  |
                  v
          Hybrid ML Evidence
                  |
                  v
          LangGraph Workflow
                  |
                  v
        Investigation Agent
                  |
                  v
        Final SOC Assessment
```

---

## 3. Machine Learning Objectives

The ML subsystem is designed to support several SOC tasks:

- classify network traffic
- distinguish benign and suspicious behavior
- detect anomalous network activity
- provide model probabilities and scores
- provide additional evidence to the AI investigation
- complement rule-based IDS detections
- reduce dependence on a single detection mechanism

Machine Learning is therefore used as a decision-support component.

---

## 4. Implemented Models

The current prototype uses three main ML approaches:

```text
Random Forest
XGBoost
Isolation Forest
```

Random Forest and XGBoost provide supervised classification evidence.

Isolation Forest provides unsupervised anomaly-detection evidence.

This creates a hybrid detection architecture.

---

## 5. Random Forest

Random Forest is used as a supervised classifier.

Conceptually:

```text
Network Features
      |
      v
Random Forest
      |
      v
Class Prediction
      |
      v
Probability Evidence
```

The model can provide classification information such as whether the supplied feature vector is closer to learned benign or attack behavior.

The prediction is preserved as evidence for later investigation.

---

## 6. XGBoost

XGBoost provides a second supervised classification perspective.

Conceptually:

```text
Network Features
      |
      v
XGBoost
      |
      v
Class Prediction
      |
      v
Probability Evidence
```

Using more than one supervised model allows the SOC workflow to observe agreement or disagreement between classifiers.

The Investigation Agent can use this information when reasoning about an incident.

---

## 7. Isolation Forest

Isolation Forest is used for anomaly detection.

Unlike the supervised classifiers, it does not need to assign the event to a previously learned attack class.

Instead, it evaluates whether the feature vector appears anomalous compared with learned behavior.

Conceptually:

```text
Network Features
      |
      v
Isolation Forest
      |
      +----------------+
      |                |
      v                v
Normal             Anomalous
                       |
                       v
                 Anomaly Score
```

This is useful for identifying suspicious behavior that may not be strongly classified by supervised models.

---

## 8. Hybrid Detection

The platform does not force all models to produce the same conclusion.

For example:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

This disagreement is useful security information.

It may indicate that:

- the event does not resemble known attack classes strongly enough for supervised classification
- the behavior is statistically unusual
- additional investigation is required

The system preserves this disagreement rather than replacing it with a simplistic majority vote.

---

## 9. Why Model Disagreement Matters

A SOC analyst should not interpret:

```text
BENIGN
```

from one classifier as proof that an event is safe.

Similarly:

```text
ANOMALY
```

does not automatically mean that an attack occurred.

The hybrid architecture therefore follows:

```text
ML Result = Evidence
```

rather than:

```text
ML Result = Final Security Decision
```

The final assessment is produced using broader incident context.

---

## 10. Supported Datasets

The ML subsystem includes support for cybersecurity datasets used for network intrusion research.

The current project includes adapters for:

```text
CICIDS2017
CSE-CIC-IDS2018
UNSW-NB15
```

These datasets do not necessarily use identical feature names or schemas.

Dataset adapters are therefore required.

---

## 11. CICIDS2017

CICIDS2017 contains labeled network traffic representing benign activity and multiple attack scenarios.

It provides flow-oriented features that can be used for supervised network intrusion classification.

Examples of feature categories include:

- packet counts
- flow duration
- packet lengths
- forward traffic
- backward traffic
- inter-arrival characteristics
- TCP-related information

The project uses a normalized feature representation so that model input remains consistent.

---

## 12. CSE-CIC-IDS2018

CSE-CIC-IDS2018 uses many concepts similar to CICIDS2017 but contains differences in column naming.

For example, dataset columns may use shortened names such as:

```text
Dst Port
Tot Fwd Pkts
Tot Bwd Pkts
TotLen Fwd Pkts
TotLen Bwd Pkts
```

while the internal normalized representation may expect names such as:

```text
Destination Port
Total Fwd Packets
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
```

The dataset adapter translates these differences.

---

## 13. Dataset Adapter

The adapter layer prevents the ML pipeline from depending directly on every external dataset's original column naming convention.

Conceptually:

```text
External Dataset
      |
      v
Dataset Adapter
      |
      v
Normalized Columns
      |
      v
Feature Pipeline
      |
      v
ML Model
```

This improves reuse across datasets.

---

## 14. Feature Mapping

A mapping strategy is used when dataset column names differ.

Conceptually:

```python
{
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets"
}
```

The complete mapping is maintained in the application ML adapter implementation.

The objective is to normalize semantically equivalent features before model processing.

---

## 15. UNSW-NB15

UNSW-NB15 is also supported through the dataset adaptation layer.

Its original schema differs more significantly from the CICIDS family.

The adapter allows the project to work with a common internal representation where compatible features can be derived or mapped.

This supports experimentation across different intrusion-detection datasets without rewriting the complete ML pipeline.

---

## 16. Data Preparation

Before ML inference or training, network data may require preparation such as:

```text
Column normalization
        |
        v
Feature selection
        |
        v
Missing-value handling
        |
        v
Numeric conversion
        |
        v
Model-compatible vector
```

The exact transformations depend on the model and dataset.

The important requirement is that inference uses the same feature semantics expected by the trained model.

---

## 17. Feature Consistency

Feature consistency is critical.

A model trained using:

```text
Feature A
Feature B
Feature C
```

must not receive:

```text
Feature B
Feature C
Feature A
```

as though the order were equivalent.

The ML pipeline therefore maintains a defined feature representation for model input.

Dataset adaptation occurs before model inference.

---

## 18. Suricata Integration

The ML subsystem includes a dedicated Suricata anomaly endpoint:

```http
POST /ml/suricata-anomaly
```

This endpoint allows compatible network event information to be evaluated by the anomaly-detection pipeline.

Suricata remains responsible for IDS detection.

Machine Learning provides an additional analytical layer.

---

## 19. Suricata Feature Safety

The anomaly feature representation should describe network behavior rather than simply copying the IDS decision.

For this reason, the feature set does not use the presence of a Suricata alert itself as a direct ML feature.

This avoids the circular logic:

```text
Suricata says attack
        |
        v
ML receives "alerted = true"
        |
        v
ML says anomalous
```

Instead, the ML model should reason from network characteristics.

---

## 20. Prediction API

Supervised ML inference is exposed through:

```http
POST /ml/predict
```

The exact request schema is available through the live OpenAPI documentation:

```text
https://soc.local/docs
```

The endpoint provides model inference without requiring direct access to model files from the API client.

---

## 21. Anomaly Detection API

Suricata-compatible anomaly analysis is exposed through:

```http
POST /ml/suricata-anomaly
```

The response provides anomaly evidence that can be consumed independently or incorporated into the larger SOC workflow.

---

## 22. LangGraph Integration

Machine Learning is part of the multi-agent SOC workflow.

The implemented logical sequence is:

```text
START
  |
  v
Triage
  |
  v
Machine Learning
  |
  v
Threat Intelligence
  |
  v
Investigation
  |
  v
Human Review when required
  |
  v
Response
  |
  v
Report
  |
  v
END
```

ML analysis therefore occurs before the Investigation Agent produces its broader security assessment.

---

## 23. ML Context for the Investigation Agent

The Investigation Agent receives detailed ML evidence rather than only a single final label.

The context can contain evidence from:

```text
Random Forest
XGBoost
Isolation Forest
```

including available prediction probabilities and anomaly information.

Conceptually:

```text
Random Forest
  prediction
  probabilities

XGBoost
  prediction
  probabilities

Isolation Forest
  anomaly status
  anomaly score
```

This gives the LLM enough information to reason about model agreement or disagreement.

---

## 24. LLM Reasoning over ML Evidence

The LLM investigation prompt explicitly treats supervised classification and anomaly detection as different forms of evidence.

For example:

```text
RF  -> BENIGN
XGB -> BENIGN
IF  -> ANOMALY
```

should not automatically become:

```text
BENIGN
```

or:

```text
MALICIOUS
```

The Investigation Agent considers the disagreement together with:

- incident severity
- source information
- network context
- Threat Intelligence
- RAG evidence
- MITRE ATT&CK context

---

## 25. Example Validated Hybrid Scenario

A representative end-to-end incident demonstrated disagreement between the ML models.

Observed ML evidence included:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

The Isolation Forest produced an anomaly score indicating unusual behavior.

The AI investigation did not ignore this disagreement.

It combined the anomaly evidence with the broader incident context and classified the incident as high risk.

The resulting investigation also produced a MITRE ATT&CK mapping.

This demonstrates that the hybrid pipeline preserves multiple evidence sources instead of relying exclusively on one model.

---

## 26. MITRE ATT&CK Relationship

Machine Learning does not independently determine the authoritative MITRE ATT&CK technique.

Instead:

```text
ML Evidence
     |
     v
Investigation Agent
     |
     +---- Threat Intelligence
     |
     +---- RAG
     |
     +---- Incident Context
     |
     v
Proposed MITRE Technique
     |
     v
MITRE Validation
```

This separates statistical detection from ATT&CK knowledge validation.

---

## 27. Relationship with Threat Intelligence

Machine Learning and Threat Intelligence solve different problems.

Machine Learning answers questions such as:

```text
Does this network behavior resemble learned malicious behavior?
Is this flow statistically unusual?
```

Threat Intelligence answers questions such as:

```text
Is this IP known for malicious activity?
Has this indicator been reported?
What reputation information exists?
```

Combining both improves investigation context.

---

## 28. Relationship with RAG

RAG provides cybersecurity knowledge rather than statistical prediction.

For example, RAG can retrieve:

- MITRE ATT&CK information
- incident-response guidance
- security playbooks
- attack descriptions

The overall reasoning becomes:

```text
ML
"What does the traffic look like?"

Threat Intelligence
"What is known about the indicator?"

RAG
"What cybersecurity knowledge is relevant?"

LLM
"What does the combined evidence suggest?"
```

---

## 29. Human Oversight

Machine Learning does not directly execute defensive actions.

The ML layer cannot independently:

- block an IP
- isolate an endpoint
- disable a user
- approve a SOAR action

Sensitive operations remain protected through backend authorization and Human-in-the-Loop controls.

---

## 30. Model Safety Principle

The platform follows this principle:

```text
Detection != Decision != Response
```

Detection may come from:

```text
Wazuh
Suricata
Random Forest
XGBoost
Isolation Forest
Threat Intelligence
```

Decision support is performed through:

```text
Correlation
RAG
LLM Investigation
MITRE ATT&CK
```

Sensitive response is controlled through:

```text
RBAC
Human Review
SOAR Approval
Dry Run
Audit
```

---

## 31. Python and ML Runtime

The authoritative Docker backend runtime uses:

```text
Python 3.13
```

The backend Docker image is based on:

```text
python:3.13-slim
```

ML dependencies include technologies such as:

```text
scikit-learn
XGBoost
PyTorch
```

CPU-only PyTorch is installed in the backend Docker image.

---

## 32. Docker ML Installation

The Docker build installs CPU PyTorch using the official CPU wheel index before installing the remaining backend dependencies.

Conceptually:

```dockerfile
RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    torch
```

This avoids requiring a GPU for the academic prototype.

---

## 33. Model Deployment Philosophy

The prototype is designed to run without specialized GPU infrastructure.

This supports:

- reproducible academic demonstrations
- local Docker deployment
- CI testing
- CPU-based inference

Large-scale production ML serving is outside the current project scope.

---

## 34. Dataset Role

The datasets are used for ML development and validation.

They should not be confused with live SOC telemetry.

```text
Datasets
   |
   v
Training / Evaluation
   |
   v
ML Models

Live Wazuh / Suricata
   |
   v
Runtime SOC Evidence
   |
   v
Inference / Investigation
```

This distinction is important when evaluating prototype results.

---

## 35. Evaluation Considerations

For supervised security classification, useful evaluation measures include:

```text
Accuracy
Precision
Recall
F1-score
Confusion matrix
False-positive behavior
```

In SOC applications, accuracy alone is insufficient.

A model can achieve high accuracy while still performing poorly on rare attacks.

Recall and false-positive behavior are especially important operational considerations.

---

## 36. Anomaly Detection Evaluation

Isolation Forest has different evaluation characteristics from supervised classification.

Its output should be interpreted in terms of:

- anomaly status
- anomaly score
- expected contamination
- behavior on known benign traffic
- behavior on suspicious traffic

Anomaly detection should not be evaluated as though it were identical to a supervised attack classifier.

---

## 37. False Positives

False positives are a major concern in SOC environments.

Too many false alerts can create:

```text
Alert Fatigue
     |
     v
Reduced Analyst Attention
     |
     v
Slower Investigation
```

The hybrid design attempts to provide richer evidence so that analysts and the Investigation Agent can distinguish isolated weak signals from stronger multi-source evidence.

---

## 38. False Negatives

False negatives are also critical.

A supervised model may fail to recognize:

- unseen attack behavior
- traffic that differs from the training distribution
- new attack variants

This is one reason the platform also includes anomaly detection and non-ML security evidence.

---

## 39. Dataset Generalization

Public intrusion-detection datasets are useful for research, but they do not perfectly reproduce a real enterprise network.

Potential limitations include:

- dataset age
- synthetic or laboratory traffic
- class imbalance
- environment-specific features
- different traffic distributions
- evolving attacker behavior

Therefore benchmark performance must not be interpreted as guaranteed production detection performance.

---

## 40. Model Explainability

The current workflow improves interpretability by preserving model-specific outputs.

Instead of returning only:

```text
MALICIOUS
```

the investigation context can preserve evidence such as:

```text
Random Forest prediction
Random Forest probabilities

XGBoost prediction
XGBoost probabilities

Isolation Forest anomaly status
Isolation Forest score
```

This provides more context for analysts and AI-assisted reasoning.

---

## 41. API and Workflow Separation

The ML models can be accessed through dedicated API endpoints.

They are also integrated into the larger SOC workflow.

```text
Direct ML API
     |
     v
Prediction Result
```

and:

```text
Incident
   |
   v
LangGraph
   |
   v
ML Node
   |
   v
Investigation Context
```

This separation allows ML testing independently from full incident orchestration.

---

## 42. Testing

The ML subsystem is covered by the backend automated test suite together with other SOC components.

The complete backend regression suite currently contains:

```text
69 tests
```

The validated suite runs successfully under the Docker Python 3.13 environment.

Tests include dataset-adapter and ML-related behavior in addition to the wider backend regression coverage.

---

## 43. Continuous Integration

Backend tests are executed through GitHub Actions.

The CI workflow uses Python 3.13 and installs CPU-compatible PyTorch before the remaining requirements.

This helps detect compatibility regressions in the ML stack.

---

## 44. Current Scope

The current ML scope includes:

```text
Random Forest supervised classification
XGBoost supervised classification
Isolation Forest anomaly detection
CICIDS2017 dataset support
CSE-CIC-IDS2018 dataset adaptation
UNSW-NB15 dataset adaptation
Suricata anomaly analysis
LangGraph ML integration
Detailed ML evidence for LLM investigation
```

---

## 45. Current Limitations

The current academic prototype has several ML limitations.

It does not claim:

- perfect attack detection
- zero false positives
- zero false negatives
- production-scale model serving
- automatic retraining from live SOC traffic
- detection of every attack family
- full end-to-end validation of every dataset attack category
- replacement of signature-based IDS systems

These limitations are important when interpreting results.

---

## 46. Future Improvements

Possible future ML improvements include:

- automated model retraining
- model versioning
- drift detection
- feature monitoring
- SHAP-based explainability
- larger cross-dataset evaluation
- online learning
- richer temporal features
- sequence-based detection
- deep-learning experimentation
- production model registry
- adversarial ML evaluation

These are potential extensions and are not claimed as current prototype functionality.

---

## 47. ML Summary

The implemented ML architecture follows:

```text
Security Data
     |
     v
Feature Adaptation
     |
     +---------------------+
     |                     |
     v                     v
Random Forest          Isolation Forest
XGBoost
     |                     |
     +----------+----------+
                |
                v
        Hybrid ML Evidence
                |
                v
         LangGraph SOC
                |
                v
       Investigation Agent
                |
        +-------+-------+
        |               |
        v               v
Threat Intelligence    RAG
        |               |
        +-------+-------+
                |
                v
         LLM Reasoning
                |
                v
          MITRE ATT&CK
                |
                v
          Human Review
```

Machine Learning strengthens the SOC investigation by providing statistical evidence, while final security reasoning remains contextual and sensitive response actions remain controlled by authorization and human oversight.