# Mathematical Model & Formulation Document

> **Project Title:** AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications  
> **Institution:** NMIT — Department of Information Science and Engineering  
> **Academic Year:** 2025–2026

---

## 1. Executive Summary

This document provides the formal mathematical and statistical formulation of the **AIOps runtime threat detection and containment framework**. 

The system formulates container security monitoring as an **unsupervised manifold learning and anomaly detection problem**. The architecture comprises three mathematical tiers:
1. **Statistical Feature Engineering & Information Theory**: Quantifying temporal dynamics, system call transitions, and port entropy.
2. **Undercomplete Deep Autoencoder**: Learning the low-dimensional manifold of benign container runtime telemetry.
3. **Statistical Decision Boundary & Risk Scoring**: Estimating reconstruction error distribution and dynamic percentile thresholding for automated containment.

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│   Raw Telemetry Stream  │ ──► │  Feature Space (R^D)    │ ──► │ Latent Manifold (R^32)  │
│   Syscalls, Net, Proc   │     │  Entropy, Rates, Ngrams │     │  Encoder Bottleneck     │
└─────────────────────────┘     └─────────────────────────┘     └───────────┬─────────────┘
                                                                            │
┌─────────────────────────┐     ┌─────────────────────────┐                 ▼
│  Action / Containment   │ ◄── │  Risk Score / Decision  │ ◄── ┌─────────────────────────┐
│  NetworkPolicy Isolate  │     │  MSE > P95 Threshold    │     │   Reconstructed (R^D)   │
└─────────────────────────┘     └─────────────────────────┘     │    Decoder Output x̂     │
                                                                └─────────────────────────┘
```

---

## 2. Feature Space Formulation $\mathcal{X} \subset \mathbb{R}^D$

Let an event stream emitted by Falco within a sliding observation window $\Delta t = 60\text{s}$ for pod $p$ be represented as $\mathcal{E}_p = \{e_1, e_2, \dots, e_N\}$. Each event $e_i$ contains timestamp $t_i$, system call $s_i$, network destination port $d_i$, and process $r_i$.

### 2.1 Information Theory: Shannon Entropy for Port Distribution
Port scanning attacks (e.g., MITRE ATT&CK T1046) exhibit uniform random dispersion across network ports. We quantify this uncertainty using **Shannon Entropy**:

$$H(P) = -\sum_{j=1}^{K} p(d_j) \log_2 \big(p(d_j) + \epsilon\big)$$

Where:
* $K$ is the number of distinct destination ports contacted in window $\Delta t$.
* $p(d_j) = \frac{\text{Count}(d_j)}{\sum_{k=1}^K \text{Count}(d_k)}$ is the empirical probability distribution of port $d_j$.
* $\epsilon = 10^{-10}$ is a smoothing factor preventing $\log_2(0)$ divergence.

**Interpretation:**
* $H(P) \to 0$: Deterministic, single-port communication (benign web service on port 80/443).
* $H(P) \to \log_2 K$: High randomness and uniform dispersion across ports (active horizontal/vertical port scanning).

### 2.2 Temporal Dynamics & Event Arrival Rate
The temporal density of events distinguishes burst attacks (DDoS, brute-force T1110) from steady-state background processes:

$$\Delta t_{\text{session}} = \max\Big(t_{\max} - t_{\min}, \, 1.0\Big)$$

$$\lambda_{\text{event}} = \frac{|\mathcal{E}_p|}{\Delta t_{\text{session}}} = \frac{N}{\Delta t_{\text{session}}}$$

$$\text{Off-Hours Flag } \mathbb{I}_{\text{off}}(t) = \begin{cases} 1, & \text{if } \text{Hour}(t) \in [22, 24] \cup [0, 6) \\ 0, & \text{otherwise} \end{cases}$$

### 2.3 Statistical Moments of Network Ports
To capture port dispersion and anomalous port targeting:

$$\bar{P}_{\text{dst}} = \frac{1}{N_{\text{net}}} \sum_{i=1}^{N_{\text{net}}} d_i$$

$$\sigma_{P_{\text{dst}}} = \sqrt{\frac{1}{N_{\text{net}} - 1} \sum_{i=1}^{N_{\text{net}}} (d_i - \bar{P}_{\text{dst}})^2}$$

### 2.4 System Call Transition N-Grams (Markovian Bigrams)
Attack sequences (e.g., privilege escalation, container escapes) follow characteristic system call execution graphs. We model transitions between consecutive system calls $(s_t, s_{t+1})$:

$$f(s_a, s_b) = \sum_{t=1}^{N-1} \mathbb{I}\big(s_t = s_a \land s_{t+1} = s_b\big)$$

Common discriminative transition pairs include:
* $\text{socket} \to \text{connect} \to \text{close}$ (Reconnaissance / Scanning)
* $\text{open} \to \text{read} \to \text{sendto}$ (Data Exfiltration)
* $\text{unshare} \to \text{mount} \to \text{chroot}$ (Container Escape / T1611)
* $\text{setuid} \to \text{execve}$ (Privilege Escalation / T1609)

---

## 3. Deep Learning Model: Undercomplete Autoencoder

Implemented in [`ml_engine/autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py).

### 3.1 Network Architecture
The network is parameterized by weights $\mathbf{W} = \{W_1, W_2, W_3, W_4, W_5, W_6\}$ and biases $\mathbf{b} = \{b_1, b_2, b_3, b_4, b_5, b_6\}$.

```
Input x ∈ R^D  ──► Linear(D, 128)  ──► BatchNorm ──► ReLU ──► h1
               ──► Linear(128, 64) ──► BatchNorm ──► ReLU ──► h2
               ──► Linear(64, 32)  ──► BatchNorm ──► ReLU ──► Latent z ∈ R^32 (Bottleneck)
               ──► Linear(32, 64)  ──► BatchNorm ──► ReLU ──► h4
               ──► Linear(64, 128) ──► BatchNorm ──► ReLU ──► h5
               ──► Linear(128, D)  ──────────────────────────► Output x̂ ∈ R^D
```

#### Encoder Mapping $f_\phi: \mathbb{R}^D \to \mathbb{R}^{32}$
$$h_1 = \text{ReLU}\big(\text{BatchNorm}_{\gamma_1, \beta_1}(W_1 x + b_1)\big), \quad W_1 \in \mathbb{R}^{128 \times D}$$
$$h_2 = \text{ReLU}\big(\text{BatchNorm}_{\gamma_2, \beta_2}(W_2 h_1 + b_2)\big), \quad W_2 \in \mathbb{R}^{64 \times 128}$$
$$z = \text{ReLU}\big(\text{BatchNorm}_{\gamma_3, \beta_3}(W_3 h_2 + b_3)\big), \quad W_3 \in \mathbb{R}^{32 \times 64}$$

Where $\text{ReLU}(u) = \max(0, u)$ and Batch Normalization for mini-batch $\mathcal{B}$ is defined as:
$$\text{BatchNorm}(u) = \gamma \left( \frac{u - \mu_{\mathcal{B}}}{\sqrt{\sigma_{\mathcal{B}}^2 + \varepsilon}} \right) + \beta$$

#### Decoder Mapping $g_\theta: \mathbb{R}^{32} \to \mathbb{R}^D$
$$h_4 = \text{ReLU}\big(\text{BatchNorm}_{\gamma_4, \beta_4}(W_4 z + b_4)\big), \quad W_4 \in \mathbb{R}^{64 \times 32}$$
$$h_5 = \text{ReLU}\big(\text{BatchNorm}_{\gamma_5, \beta_5}(W_5 h_4 + b_5)\big), \quad W_5 \in \mathbb{R}^{128 \times 64}$$
$$\hat{x} = g_\theta(z) = W_6 h_5 + b_6, \quad W_6 \in \mathbb{R}^{D \times 128}$$

*(Note: The output layer uses a linear identity activation to allow unconstrained reconstruction over the entire real domain $\mathbb{R}^D$.)*

### 3.2 Optimization Objective (MSE Loss)
The model is trained strictly on benign baseline telemetry $\mathcal{D}_{\text{benign}}$ by minimizing the empirical reconstruction risk:

$$\min_{\phi, \theta} \mathcal{L}(\phi, \theta) = \frac{1}{|\mathcal{D}_{\text{benign}}| \cdot D} \sum_{i=1}^{|\mathcal{D}_{\text{benign}}|} \sum_{j=1}^{D} \left( x_{ij} - [g_\theta(f_\phi(x_i))]_j \right)^2$$

Parameter updates are performed using the **Adam Optimizer** with adaptive first and second moment estimations:
$$m_t = \beta_1 m_{t-1} + (1 - \beta_1) \nabla_\Theta \mathcal{L}_t$$
$$v_t = \beta_2 v_{t-1} + (1 - \beta_2) (\nabla_\Theta \mathcal{L}_t)^2$$
$$\hat{m}_t = \frac{m_t}{1 - \beta_1^t}, \quad \hat{v}_t = \frac{v_t}{1 - \beta_2^t}$$
$$\Theta_{t+1} = \Theta_t - \frac{\alpha}{\sqrt{\hat{v}_t} + \varepsilon_{\text{opt}}} \hat{m}_t$$
*(where $\alpha = 10^{-3}$, $\beta_1 = 0.9$, $\beta_2 = 0.999$, $\varepsilon_{\text{opt}} = 10^{-8}$)*.

---

## 4. Anomaly Detection & Statistical Decision Theory

### 4.1 Per-Sample Reconstruction Error $S(x)$
During runtime inference, each incoming event feature vector $x$ produces an anomaly score $S(x)$ representing the squared Euclidean distance between the vector and its projection onto the learned normal manifold:

$$S(x) = \|x - \hat{x}\|_2^2 = \frac{1}{D} \sum_{j=1}^{D} (x_j - \hat{x}_j)^2$$

### 4.2 Non-Parametric Percentile Thresholding
Rather than assuming a rigid Gaussian distribution, the threshold $\tau$ is determined non-parametrically using the empirical cumulative distribution function (CDF) $F_S(s)$ of reconstruction scores on benign validation data:

$$F_S(s) = P(S \le s) = \frac{1}{M} \sum_{i=1}^{M} \mathbb{I}(S(x_i^{\text{val}}) \le s)$$

The decision threshold $\tau$ is set at the $95^{\text{th}}$ percentile ($p = 0.95$):

$$\tau = F_S^{-1}(0.95) = \inf \big\{ s \in \mathbb{R} : F_S(s) \ge 0.95 \big\}$$

This guarantees a theoretical upper bound of $5\%$ false-positive rate ($\alpha = 0.05$) under stationary benign traffic distributions.

### 4.3 Piecewise Risk Assessment & Automated Containment Function
Implemented in [`ml_engine/pipeline.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/pipeline.py#L283-L313):

$$\text{Decision}(x) = \begin{cases}
\text{CRITICAL} \implies \text{Quarantine Pod (Apply Deny-All NetworkPolicy)}, & \text{if } S(x) > 1.5 \cdot \tau \\
\text{HIGH} \implies \text{Quarantine Pod (Apply Deny-All NetworkPolicy)}, & \text{if } \tau < S(x) \le 1.5 \cdot \tau \\
\text{MEDIUM} \implies \text{Active Monitoring \& SOC Alert}, & \text{if } 0.7 \cdot \tau < S(x) \le \tau \\
\text{LOW} \implies \text{Standard Telemetry Logging}, & \text{if } S(x) \le 0.7 \cdot \tau
\end{cases}$$

---

## 5. Fallback Heuristic Scoring (Linear Risk Model)

Implemented in [`ml_engine/pipeline.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/pipeline.py#L265-L282).

When operating in offline, testing, or bootstrap mode without pre-trained model weights, the pipeline employs a bounded convex combination of normalized risk indicators:

$$S_{\text{heuristic}}(x) = \sum_{k=1}^{7} w_k \cdot \min\left( \frac{f_k}{M_k}, \, 1.0 \right)$$

Subject to the constraint:
$$\sum_{k=1}^{7} w_k = 1.0, \quad w_k \ge 0$$

| Feature Index $k$ | Feature Name $f_k$ | Weight $w_k$ | Normalization Bound $M_k$ |
|---|---|:---:|:---:|
| 1 | Severity Numeric | $0.20$ | $3$ ($\text{CRITICAL}$) |
| 2 | Event Type Encoded | $0.10$ | $9$ |
| 3 | Syscall Risk Level | $0.25$ | $3$ |
| 4 | Has Network Metadata | $0.05$ | $1$ |
| 5 | Destination Port Risk | $0.15$ | $3$ |
| 6 | External IP Flag | $0.15$ | $1$ |
| 7 | Process Risk Level | $0.10$ | $2$ |

---

## 6. Mathematical Summary Reference Table

| Formula / Concept | Mathematical Notation | Component File | Purpose |
|---|---|---|---|
| **Port Entropy** | $H(P) = -\sum p(d) \log_2 p(d)$ | [`feature_extraction.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/data_pipeline/feature_extraction.py) | Detection of horizontal and vertical port scanning |
| **Event Rate** | $\lambda = \frac{N}{\Delta t}$ | [`feature_extraction.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/data_pipeline/feature_extraction.py) | Detection of DDoS and credential brute forcing |
| **Syscall Bigrams** | $f(s_a, s_b) = \sum \mathbb{I}(s_t = s_a \land s_{t+1} = s_b)$ | [`feature_extraction.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/data_pipeline/feature_extraction.py) | Markovian modeling of attack execution sequences |
| **Autoencoder Compression** | $z = f_\phi(x) \in \mathbb{R}^{32}$ | [`autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py) | Low-dimensional manifold projection of normal state |
| **Autoencoder Reconstruction** | $\hat{x} = g_\theta(z) \in \mathbb{R}^D$ | [`autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py) | Inverse mapping from latent space back to features |
| **Training Loss** | $\mathcal{L} = \frac{1}{BD}\sum (x - \hat{x})^2$ | [`autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py) | Parameter optimization on benign telemetry |
| **Anomaly Score** | $S(x) = \frac{1}{D}\sum (x_j - \hat{x}_j)^2$ | [`autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py) | Distance from benign manifold |
| **Thresholding** | $\tau = F_S^{-1}(0.95)$ | [`autoencoder.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/autoencoder.py) | Non-parametric $95^{\text{th}}$ percentile boundary |
| **Quarantine Trigger** | $S(x) > \tau \implies \text{NetworkPolicy}$ | [`pipeline.py`](file:///c:/Users/aditya/Documents/PROJECTS/FYP/ml_engine/pipeline.py) | Automated isolation of compromised pod |
