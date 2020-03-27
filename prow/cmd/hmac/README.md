# HMAC

`hmac` is a tool to update the HMAC token, GitHub webhooks and HMAC secret
for the orgs/repos as per the `managed_webhooks` configuration changes in the Prow config file.

## How it works

Given a new `managed_webhooks` configuration, the tool can reconcile the current
state of HMAC tokens, secrets and webhooks to meet the new configuration.

### Examples

Suppose the current `managed_webhooks` configuration is
```yaml
qux:
  tokenCreatedAfter: 2017-10-02T15:00:00Z
foo/bar:
  tokenCreatedAfter: 2018-10-02T15:00:00Z
foo/baz:
  tokenCreatedAfter: 2019-10-02T15:00:00Z
``` 

There can be 3 scenarios to modify the configuration, as explained below:

#### Rotate an existing HMAC token

User updates the `tokenCreatedAfter` for `foo/baz` to a later time, as shown below:
```yaml
qux:
  tokenCreatedAfter: 2017-10-02T15:00:00Z
foo/bar:
  tokenCreatedAfter: 2018-10-02T15:00:00Z
foo/baz:
  tokenCreatedAfter: 2020-03-02T15:00:00Z
``` 

The `hmac` tool will generate a new HMAC token for the `foo/baz` repo,
add the new token to the secret, and update the webhook for the repo.
And after the update finishes, it will delete the old token.

#### Onboard a new repo

User adds a new repo `foo/bax` in the `managed_webhooks` configuration, as shown below:
```yaml
qux:
  tokenCreatedAfter: 2017-10-02T15:00:00Z
foo/bar:
  tokenCreatedAfter: 2018-10-02T15:00:00Z
foo/baz:
  tokenCreatedAfter: 2019-10-02T15:00:00Z
foo/bax:
  tokenCreatedAfter: 2020-03-02T15:00:00Z
``` 

The `hmac` tool will generate an HMAC token for the `foo/bax` repo,
add the token to the secret, and add the webhook for the repo.

#### Remove an existing repo

User deletes the repo `foo/baz` from the `managed_webhooks` configuration, as shown below:
```yaml
qux:
  tokenCreatedAfter: 2017-10-02T15:00:00Z
foo/bar:
  tokenCreatedAfter: 2018-10-02T15:00:00Z
``` 

The `hmac` tool will delete the HMAC token for the `foo/baz` repo from
the secret, and delete the corresponding webhook for this repo.

> Note the 3 types of config changes can happen together, and `hmac` tool
> is able to handle all the changes in one single run.
