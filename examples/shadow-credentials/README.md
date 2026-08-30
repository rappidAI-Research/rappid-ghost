# Shadow credentials demonstration

This local example demonstrates Ghost's first active `SHADOW` resource. It needs Docker, but no AWS account, real credential, API key, network, or paid service.

From this directory, initialize runtime storage without replacing the supplied policy:

```sh
../../bin/ghost init
```

First run a command that does not touch a decoy:

```sh
../../bin/ghost run -- echo "safe"
../../bin/ghost inspect latest
```

The inspection should list three Shadow resources as `untouched` and no security incident.

Now read the synthetic AWS file:

```sh
../../bin/ghost run -- sh -c 'cat ~/.aws/credentials'
../../bin/ghost inspect latest
```

Expected properties:

- output contains `GHOST_AWS_` and `GHOST_SECRET_` synthetic values;
- the AWS decoy is `TRIGGERED`;
- `DECOY_ACCESS` and `SECURITY_INCIDENT` appear in the event timeline;
- the SSH and `.env` decoys remain untouched;
- the inspection reports `Host home mounted: no`.

To demonstrate fail-closed behavior, change `policy.home` in `ghost.yaml` to `deny`, then run:

```sh
../../bin/ghost run -- sh -c 'test ! -e ~/.aws/credentials'
../../bin/ghost inspect latest
```

No real credential is accessed or required in any step. Session material stays under this example's ignored `.ghost/` directory.
