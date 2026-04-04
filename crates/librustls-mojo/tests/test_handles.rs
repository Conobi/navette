use librustls_mojo::handles::HandleTable;

#[test]
fn insert_and_get() {
    let table: HandleTable<String> = HandleTable::new();
    let h = table.insert(String::from("hello"));
    assert!(h > 0);
    table.with(h, |val| assert_eq!(val, &"hello")).unwrap();
}

#[test]
fn remove_and_get_fails() {
    let table: HandleTable<String> = HandleTable::new();
    let h = table.insert(String::from("world"));
    assert!(table.remove(h).is_some());
    assert!(table.with(h, |_| ()).is_none());
}

#[test]
fn double_remove_returns_none() {
    let table: HandleTable<i32> = HandleTable::new();
    let h = table.insert(42);
    assert!(table.remove(h).is_some());
    assert!(table.remove(h).is_none());
}

#[test]
fn invalid_handle_returns_none() {
    let table: HandleTable<String> = HandleTable::new();
    assert!(table.with(99999, |_| ()).is_none());
}

#[test]
fn handles_are_unique() {
    let table: HandleTable<u8> = HandleTable::new();
    let h1 = table.insert(1);
    let h2 = table.insert(2);
    assert_ne!(h1, h2);
}

#[test]
fn get_mut_works() {
    let table: HandleTable<String> = HandleTable::new();
    let h = table.insert(String::from("before"));
    table.with_mut(h, |val| *val = String::from("after")).unwrap();
    table.with(h, |val| assert_eq!(val, &"after")).unwrap();
}
