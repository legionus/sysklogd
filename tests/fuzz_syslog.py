#!/usr/bin/env python3

from boofuzz import *

def main():
    session = Session(
        target=Target(connection=UDPSocketConnection("127.0.0.1", 514)),
        receive_data_after_each_request=False,
        ignore_connection_reset=False,
        ignore_connection_aborted=False,
        keep_web_open=False,
    )

    s_initialize(name="Syslog")

    with s_block("Syslog-Message"):
        # Priority
        s_delim("<")
        s_bit_field(0, width=8, output_format="ascii", name="priority")
        s_delim(">")

        # Date
        s_group("month", ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov","Dec"])
        s_delim(" ")
        s_long(11, output_format="ascii", name="day")
        s_delim(" ")
        s_long(22, output_format="ascii", name="hour")
        s_delim(":")
        s_long(14, output_format="ascii", name="minute")
        s_delim(":")
        s_long(15, output_format="ascii", name="second")
        s_delim(" ")

        # Hostname
        s_string("myhost.example.com", name="hostname")
        s_delim(" ")

        # Tag
        s_string("su", name="tag", max_len=40)
        s_delim(": ")

        # Message
        s_size("Message-Part", output_format="ascii")

    with s_block("Message-Part"):
        s_string("abc", name="message", max_len=3000)

    session.connect(s_get("Syslog"))

    print("start fuzzing...")
    session.fuzz()
    print("done fuzzing.")


if __name__ == "__main__":
    main()
