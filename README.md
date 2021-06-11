# VITA 49.2 Wireshark Dissector

Wireshark plugin for dissecting V49.2 packets. The `vrtgen` data model is used
to create the packet field accessors. Using this plugin in place of Wireshark's
built-in dissector allows viewing the contents of context and command packets.

Building this project creates a `v49d2.so` loadable module that can be installed
to the Wireshark `plugins` directory.

## Dependencies

The `v49d2.so` module requires Wireshark and Wireshark development package >= 2.6.

Building the module from source requires CMake 3.14 or newer and Python 3.6 or
newer with `vrtgen` installed.

## Installation

The `vrtgen` Python module must be available to generate the source code used in
the module. The source is included as a Git submodule, but must be installed first.
The easiest way to install it is with the use of a Python virtual environment:

```sh
python3 -m venv venv
. venv/bin/activate
pushd vrtgen
pip install .
popd
```

As long as the `vrtgen` module can be imported by the Python 3 interpreter,
CMake will detect it and generate the necessary files. 

```sh
python3 -c "import vrtgen; print('vrtgen installed')"
```

To build the project:

```sh
cmake3 -B build
cd build
sudo make install
```

## Usage

When the `v49d2.so` module is installed, Wireshark shows "VITA 49.2" in the
protocol list. Right-click on a captured packet and select "Decode As..." to
bring up the protocol selection dialog, then select "VITA 49.2" and click "OK".

## Testing

The `pcaps` directory includes some sample Wireshark captures that exercise the
dissector for common data, context and command packets.
