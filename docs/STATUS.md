# Current status

Six shared Python modules, regression tests and an offline JSON CLI are available. The [README](../README.md) lists the code, commands and test instructions; [source inventory](SOURCE_REVIEW.md) records module hashes and dependency scope.

The full desktop application and MSI are not included. Service Mode and dependent widget deployment remain outside this repository. Final project use/license terms remain under review. The [work queue](TASKS.md) tracks the remaining migration.

Standalone camera grafting source now covers Z8, Z40 and Hub extraction, gate 1, application construction/verification and gate 2. The camera source receipt and import check are separate from the six-module shared-runtime contract. Vendor inputs, native helper/tool binaries and private application services are excluded. See [camera instructions](CAMERA_GRAFTING.md). Synthetic regression evidence does not qualify hardware or a new donor version.


Camera export validation:126default tests and27subtests passed. With locally supplied exact-version images,43adversarial image regressions passed in isolated target processes (7unchanged-donor,13Z40,11Z8,12Hub); no image fixtures or vendor assets are checked in. Current fixtures include the production updater-identity delta from the pinned donor. Import/inventory/privacy checks passed. See CAMERA_VALIDATION.json.
