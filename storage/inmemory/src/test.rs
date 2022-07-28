use storage_core::traits::*;

storage_core::decl_schema! {
    MySchema {
        MyMap: Single,
    }
}

type MyStore = crate::Store<MySchema>;

fn generic_aborted_write<St: Backend<MySchema>>(store: &St) -> storage_core::Result<()> {
    store.transaction_rw().run(|tx| {
        tx.get_mut::<MyMap, _>().put(b"hello".to_vec(), b"world".to_vec())?;
        storage_core::abort(())
    })
}

#[test]
fn test_abort() {
    common::concurrency::model(|| {
        let store = MyStore::default();

        let r = generic_aborted_write(&store);
        assert_eq!(r, Ok(()));

        let r = store
            .transaction_ro()
            .run(|tx| Ok(tx.get::<MyMap, _>().get(b"hello")?.is_some()));
        assert_eq!(r, Ok(false));
    })
}
