//! Read-only Windows inventory. All MIB allocations are freed on every exit path.
use super::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceManagerError,
    classify_interface,
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    NetworkManagement::{
        IpHelper::{
            FreeMibTable, GetIfTable2, GetUnicastIpAddressTable, MIB_IF_ROW2, MIB_IF_TABLE2,
            MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
        },
        Ndis::NET_IF_OPER_STATUS_UP,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

const MAX_INTERFACES: usize = 4096;
const MAX_ADDRESSES: usize = 16384;

struct MibAllocation(*mut std::ffi::c_void);
impl Drop for MibAllocation {
    fn drop(&mut self) {
        // SAFETY: only successful, non-null IP Helper allocations enter this guard.
        unsafe { FreeMibTable(self.0) };
    }
}

fn bounded_count<T>(count: u32, maximum: usize) -> Result<usize, InterfaceManagerError> {
    let count = count as usize;
    if count > maximum || count > isize::MAX as usize / size_of::<T>() {
        return Err(InterfaceManagerError::Capacity);
    }
    Ok(count)
}

fn text(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn interface(
    row: &MIB_IF_ROW2,
    addresses: Vec<Address>,
) -> Result<Interface, InterfaceManagerError> {
    if row.InterfaceIndex == 0 {
        return Err(InterfaceManagerError::InvalidInterfaceIndex);
    }
    let name = text(&row.Alias);
    let description = text(&row.Description);
    let mut class = classify_interface(&name, Some(&description), row.Type == 24);
    let hardware = row.InterfaceAndOperStatusFlags._bitfield & 1 != 0;
    if !hardware
        && matches!(
            class,
            InterfaceClass::PhysicalWired | InterfaceClass::PhysicalWifi
        )
    {
        class = InterfaceClass::Unknown;
    } else if hardware && class == InterfaceClass::Unknown {
        class = match row.Type {
            6 => InterfaceClass::PhysicalWired,
            71 => InterfaceClass::PhysicalWifi,
            _ => InterfaceClass::Unknown,
        };
    }
    Ok(Interface {
        id: InterfaceId::new(row.InterfaceIndex),
        name,
        description: (!description.is_empty()).then_some(description),
        up: row.OperStatus == NET_IF_OPER_STATUS_UP,
        class,
        addresses,
        owner_role: None,
    })
}

pub(super) fn snapshot() -> Result<InterfaceInventory, InterfaceManagerError> {
    let mut interfaces: *mut MIB_IF_TABLE2 = ptr::null_mut();
    // SAFETY: initialized out-pointer; the OS allocates its documented table.
    if unsafe { GetIfTable2(&mut interfaces) } != ERROR_SUCCESS || interfaces.is_null() {
        return Err(InterfaceManagerError::Unavailable);
    }
    let _interfaces_guard = MibAllocation(interfaces.cast());
    let mut unicast: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    // SAFETY: initialized out-pointer, same allocation contract as GetIfTable2.
    if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut unicast) } != ERROR_SUCCESS
        || unicast.is_null()
    {
        return Err(InterfaceManagerError::Unavailable);
    }
    let _unicast_guard = MibAllocation(unicast.cast());
    // SAFETY: both tables are successful non-null allocations owned by the guards.
    let count = bounded_count::<MIB_IF_ROW2>(unsafe { (*interfaces).NumEntries }, MAX_INTERFACES)?;
    let address_count =
        bounded_count::<MIB_UNICASTIPADDRESS_ROW>(unsafe { (*unicast).NumEntries }, MAX_ADDRESSES)?;
    // SAFETY: Table begins the variable-length array in each documented MIB allocation.
    let first_interface = unsafe { (*interfaces).Table.as_ptr() };
    let first_address = unsafe { (*unicast).Table.as_ptr() };
    let mut by_interface: BTreeMap<u32, Vec<Address>> = BTreeMap::new();
    for i in 0..address_count {
        // SAFETY: the OS owns the row-count contract; the count is bounded above.
        let row = unsafe { &*first_address.add(i) };
        if row.InterfaceIndex == 0 || row.ValidLifetime == 0 {
            continue;
        }
        // SAFETY: the initialized family selects the corresponding union variant.
        let family = unsafe { row.Address.si_family };
        let ip = match family {
            AF_INET if row.OnLinkPrefixLength <= 32 => IpAddr::V4(Ipv4Addr::from(
                unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
            )),
            AF_INET6 if row.OnLinkPrefixLength <= 128 => {
                IpAddr::V6(Ipv6Addr::from(unsafe { row.Address.Ipv6.sin6_addr.u.Byte }))
            }
            _ => continue,
        };
        if !ip.is_unspecified() {
            by_interface
                .entry(row.InterfaceIndex)
                .or_default()
                .push(Address {
                    ip,
                    prefix: row.OnLinkPrefixLength,
                });
        }
    }
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: the guard retains the OS table and i is less than its bounded count.
        let row = unsafe { &*first_interface.add(i) };
        let mut addresses = by_interface.remove(&row.InterfaceIndex).unwrap_or_default();
        addresses.sort_by_key(|address| (address.ip, address.prefix));
        addresses.dedup();
        result.push(interface(row, addresses)?);
    }
    Ok(InterfaceInventory::new(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_inventory_has_usable_indices_and_valid_prefixes() {
        let snapshot = snapshot().expect("read-only Windows IP Helper inventory");
        assert!(snapshot.interfaces().next().is_some());
        for interface in snapshot.interfaces() {
            assert_ne!(interface.id.get(), 0);
            for address in &interface.addresses {
                assert!(address.prefix <= if address.ip.is_ipv4() { 32 } else { 128 });
            }
        }
    }
    #[test]
    fn virtual_ethernet_does_not_gain_discovery_authority_from_its_name() {
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: 7,
            Type: 6,
            OperStatus: NET_IF_OPER_STATUS_UP,
            ..Default::default()
        };
        for (slot, unit) in row.Alias.iter_mut().zip("Ethernet".encode_utf16()) {
            *slot = unit;
        }
        assert_eq!(
            interface(&row, vec![]).unwrap().class,
            InterfaceClass::Unknown
        );
        row.InterfaceAndOperStatusFlags._bitfield = 1;
        assert_eq!(
            interface(&row, vec![]).unwrap().class,
            InterfaceClass::PhysicalWired
        );
    }
    #[test]
    fn table_and_string_processing_stay_bounded() {
        assert!(bounded_count::<MIB_IF_ROW2>(4097, MAX_INTERFACES).is_err());
        assert_eq!(text(&[65, 0, 66]), "A");
        assert_eq!(text(&[65, 66]), "AB");
    }
}
