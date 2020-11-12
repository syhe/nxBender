#!/bin/sh -e

# dns script with support for systemd-resolved
# copied from https://github.com/systemd/systemd/issues/481#issuecomment-541423103

# this variable is only set if the usepeerdns pppd option is being used
[ "$USEPEERDNS" ] || exit 0

if [ "${DNS1}" ]; then
  if [ "${DNS2}" ]; then
    /usr/bin/resolvectl dns "${IFNAME}" "${DNS1}" "${DNS2}"
  else
    /usr/bin/resolvectl dns "${IFNAME}" "${DNS1}"
  fi
fi

exit 0
