# Barrage

Barrage will be an app that can send multiple messages to a HTTP- or TCP-endpoint of choice.
It's main purpose is to fire off events to event busses and other applications that need their message throughput measured.

## Checklist

This contains the next work-items that need to be done

- [ ] Read the rust CLI book: IN PROGRESS
- [ ] `cargo add tokio` for async threading + read up on how it works.
      `crossbeam-channel` could be used if there needs to be message passing, but I think thats not necessary.
- [ ] check if we need the crate `exitcode` for different exit codes.
- [ ] use `human_panic` to panic and refer to the github or whatever for issues.
- [ ] the recorded stats of the messages that are sent and not sent should be saved to file at the end of the program.
- [ ] check out mangen for an automatic way to generate a man page.
      the examples there also have a pretty good basic example for a cli page.
      use this and other examples to create the sender.


IF we need more handlers for events, then use `signal-hook` instead of the current `ctrlc` package.
`ctrlc` only listens for SIGINT on unix systems.

## Features

//todo create the requirements here
