# Strike - Load testing for Health Messages

Strike is a command line tool that allows you to put consumers of HL7-messages under load.
This is useful for testing and benchmarking HL7-brokers like mirth.
It can also be used when writing your own consumer applications for HL7 messages, and to generate some kind of continuous load.</br>

## Features

1. A straightforward method to configure the sender.
2. Pretty good threading (I hope)
3. A simple view of the `live stats` about the messages that are sent to the consumer. Contains `sent` and `failed` messages, along with a `message rate` of sent messages.

## Installing `strike`

Installing strike as a cli tool through cargo can be done with the following command: 

`cargo install strike`.

## Configuring `strike`

Strike allows for config through the `strike.conf` file.
The CLI also allows you to manage the configuration. `strike config`.

`strike config show` shows the current configuration.
`strike config set --help` shows all possible settings.

## Using `strike`

`strike test-connection` will test the connection as it is configured.

`strike send` will start sending messages, and will show the live view.
You can always stop the tool by pressing `CTRL+C`.

## Future work

The following features are some things that I still want to attempt in this package:

- [ ] Improve the live stats view, including information about the endpoint.
- [ ] Make the 'message rate' configurable, so that you can run this tool as a constant (manageable) stream of messages.
