use salsa::DbWithJar;

use ruff_db::{Db as SourceDb, Upcast};

use red_knot_module_resolver::Db as ResolverDb;

use crate::semantic_index::definition::Definition;
use crate::semantic_index::symbol::{public_symbols_map, PublicSymbolId, ScopeId};
use crate::semantic_index::{root_scope, semantic_index, symbol_table};
use crate::types::{infer_types, public_symbol_ty};

#[salsa::jar(db=Db)]
pub struct Jar(
    ScopeId<'_>,
    PublicSymbolId<'_>,
    Definition<'_>,
    symbol_table,
    root_scope,
    semantic_index,
    infer_types,
    public_symbol_ty,
    public_symbols_map,
);

/// Database giving access to semantic information about a Python program.
pub trait Db:
    SourceDb + ResolverDb + DbWithJar<Jar> + Upcast<dyn SourceDb> + Upcast<dyn ResolverDb>
{
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Formatter;
    use std::marker::PhantomData;
    use std::sync::Arc;

    use salsa::id::AsId;
    use salsa::ingredient::Ingredient;
    use salsa::storage::HasIngredientsFor;
    use salsa::DebugWithDb;

    use red_knot_module_resolver::{Db as ResolverDb, Jar as ResolverJar};
    use ruff_db::file_system::{FileSystem, MemoryFileSystem, OsFileSystem};
    use ruff_db::vfs::Vfs;
    use ruff_db::{Db as SourceDb, Jar as SourceJar, Upcast};

    use super::{Db, Jar};

    #[salsa::db(Jar, ResolverJar, SourceJar)]
    pub(crate) struct TestDb {
        storage: salsa::Storage<Self>,
        vfs: Vfs,
        file_system: TestFileSystem,
        events: std::sync::Arc<std::sync::Mutex<Vec<salsa::Event>>>,
    }

    impl TestDb {
        pub(crate) fn new() -> Self {
            Self {
                storage: salsa::Storage::default(),
                file_system: TestFileSystem::Memory(MemoryFileSystem::default()),
                events: std::sync::Arc::default(),
                vfs: Vfs::with_stubbed_vendored(),
            }
        }

        /// Returns the memory file system.
        ///
        /// ## Panics
        /// If this test db isn't using a memory file system.
        pub(crate) fn memory_file_system(&self) -> &MemoryFileSystem {
            if let TestFileSystem::Memory(fs) = &self.file_system {
                fs
            } else {
                panic!("The test db is not using a memory file system");
            }
        }

        #[allow(unused)]
        pub(crate) fn vfs_mut(&mut self) -> &mut Vfs {
            &mut self.vfs
        }

        /// Takes the salsa events.
        ///
        /// ## Panics
        /// If there are any pending salsa snapshots.
        pub(crate) fn take_salsa_events(&mut self) -> Vec<salsa::Event> {
            let inner = Arc::get_mut(&mut self.events).expect("no pending salsa snapshots");

            let events = inner.get_mut().unwrap();
            std::mem::take(&mut *events)
        }

        /// Clears the salsa events.
        ///
        /// ## Panics
        /// If there are any pending salsa snapshots.
        pub(crate) fn clear_salsa_events(&mut self) {
            self.take_salsa_events();
        }
    }

    impl SourceDb for TestDb {
        fn file_system(&self) -> &dyn FileSystem {
            match &self.file_system {
                TestFileSystem::Memory(fs) => fs,
                TestFileSystem::Os(fs) => fs,
            }
        }

        fn vfs(&self) -> &Vfs {
            &self.vfs
        }
    }

    impl Upcast<dyn SourceDb> for TestDb {
        fn upcast(&self) -> &(dyn SourceDb + 'static) {
            self
        }
    }

    impl Upcast<dyn ResolverDb> for TestDb {
        fn upcast(&self) -> &(dyn ResolverDb + 'static) {
            self
        }
    }

    impl red_knot_module_resolver::Db for TestDb {}
    impl Db for TestDb {}

    impl salsa::Database for TestDb {
        fn salsa_event(&self, event: salsa::Event) {
            tracing::trace!("event: {:?}", event.debug(self));
            let mut events = self.events.lock().unwrap();
            events.push(event);
        }
    }

    impl salsa::ParallelDatabase for TestDb {
        fn snapshot(&self) -> salsa::Snapshot<Self> {
            salsa::Snapshot::new(Self {
                storage: self.storage.snapshot(),
                vfs: self.vfs.snapshot(),
                file_system: match &self.file_system {
                    TestFileSystem::Memory(memory) => TestFileSystem::Memory(memory.snapshot()),
                    TestFileSystem::Os(fs) => TestFileSystem::Os(fs.snapshot()),
                },
                events: self.events.clone(),
            })
        }
    }

    enum TestFileSystem {
        Memory(MemoryFileSystem),
        #[allow(dead_code)]
        Os(OsFileSystem),
    }

    pub(crate) fn assert_will_run_function_query<'db, C, Db, Jar>(
        db: &'db Db,
        to_function: impl FnOnce(&C) -> &salsa::function::FunctionIngredient<C>,
        input: &C::Input<'db>,
        events: &[salsa::Event],
    ) where
        C: salsa::function::Configuration<Jar = Jar>
            + salsa::storage::IngredientsFor<Jar = Jar, Ingredients = C>,
        Jar: HasIngredientsFor<C>,
        Db: salsa::DbWithJar<Jar>,
        C::Input<'db>: AsId,
    {
        will_run_function_query(db, to_function, input, events, true);
    }

    pub(crate) fn assert_will_not_run_function_query<'db, C, Db, Jar>(
        db: &'db Db,
        to_function: impl FnOnce(&C) -> &salsa::function::FunctionIngredient<C>,
        input: &C::Input<'db>,
        events: &[salsa::Event],
    ) where
        C: salsa::function::Configuration<Jar = Jar>
            + salsa::storage::IngredientsFor<Jar = Jar, Ingredients = C>,
        Jar: HasIngredientsFor<C>,
        Db: salsa::DbWithJar<Jar>,
        C::Input<'db>: AsId,
    {
        will_run_function_query(db, to_function, input, events, false);
    }

    fn will_run_function_query<'db, C, Db, Jar>(
        db: &'db Db,
        to_function: impl FnOnce(&C) -> &salsa::function::FunctionIngredient<C>,
        input: &C::Input<'db>,
        events: &[salsa::Event],
        should_run: bool,
    ) where
        C: salsa::function::Configuration<Jar = Jar>
            + salsa::storage::IngredientsFor<Jar = Jar, Ingredients = C>,
        Jar: HasIngredientsFor<C>,
        Db: salsa::DbWithJar<Jar>,
        C::Input<'db>: AsId,
    {
        let (jar, _) =
            <_ as salsa::storage::HasJar<<C as salsa::storage::IngredientsFor>::Jar>>::jar(db);
        let ingredient = jar.ingredient();

        let function_ingredient = to_function(ingredient);

        let ingredient_index =
            <salsa::function::FunctionIngredient<C> as Ingredient<Db>>::ingredient_index(
                function_ingredient,
            );

        let did_run = events.iter().any(|event| {
            if let salsa::EventKind::WillExecute { database_key } = event.kind {
                database_key.ingredient_index() == ingredient_index
                    && database_key.key_index() == input.as_id()
            } else {
                false
            }
        });

        if should_run && !did_run {
            panic!(
                "Expected query {:?} to run but it didn't",
                DebugIdx {
                    db: PhantomData::<Db>,
                    value_id: input.as_id(),
                    ingredient: function_ingredient,
                }
            );
        } else if !should_run && did_run {
            panic!(
                "Expected query {:?} not to run but it did",
                DebugIdx {
                    db: PhantomData::<Db>,
                    value_id: input.as_id(),
                    ingredient: function_ingredient,
                }
            );
        }
    }

    struct DebugIdx<'a, I, Db>
    where
        I: Ingredient<Db>,
    {
        value_id: salsa::Id,
        ingredient: &'a I,
        db: PhantomData<Db>,
    }

    impl<'a, I, Db> std::fmt::Debug for DebugIdx<'a, I, Db>
    where
        I: Ingredient<Db>,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            self.ingredient.fmt_index(Some(self.value_id), f)
        }
    }
}
