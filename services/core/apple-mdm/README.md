# Apple MDM and Automated Device Enrollment

This service contains Apple MDM enrollment, APNs and command plumbing. It has **no connected or accepted Apple Business / Apple School Manager ADE connector**. A local device record or blueprint assignment does not establish Apple enrollment or execution on a device.

The legacy `GET /api/mdm/dep/devices` and admin-only `POST /api/mdm/dep/assign` return `503 apple_ade_not_configured`. Simulated serial numbers and in-memory assignment success have been removed. Authentication and admin checks still apply. The Blueprint ADE tab explains setup and displays an unavailable state when inventory cannot be read.

See the [ADE setup guide](../../../docs/integrations/apple-automated-device-enrollment.md) for purchasing, supplier IDs, Apple Configurator and the boundary between Apple assignment and MDM enrollment. [SAML/OIDC authentication](../oauth-provider/README.md) is separate.

Run `npm install --ignore-scripts` and `npm test` here. Tests check API authentication, admin restrictions and that unavailable Apple integration never reports inventory or successful assignments. They do not enroll, push to, lock or erase real Apple devices.
