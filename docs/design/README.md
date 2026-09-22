# Design, as it was proposed

Three documents written before any of the lab existed, kept as submitted. They were the first
three steps of the coursework brief this project started from: what the problem was, what
would count as solving it, and what the stack should be.

| | |
| --- | --- |
| [context-analysis.md](context-analysis.md) | Why a small organisation needs this, and what a detection lab is for. Includes the PlantUML system context diagram. |
| [problem-and-scope.md](problem-and-scope.md) | The three scenarios S1 to S3, and the acceptance requirements R1 to R5. |
| [technical-design.md](technical-design.md) | The proposed stack: Wazuh, the guests, and how detection would be tested. |

They are here as a record of what was proposed, not as a description of what exists. The stack
was confirmed almost unchanged and the requirements were met, but the build moved a long way
past this in places these pages know nothing about: two hypervisors instead of one, cloud
images instead of an installer, a scoring layer, and a dataset.

Where these disagree with the repository, the repository is what happened.
[docs/implementation.md](../implementation.md) is the technical record, R1 to R5 against
evidence. [PROJECT-STATUS.md](../../PROJECT-STATUS.md) is what has moved since.
