use firestore::FirestoreDb;

use crate::{Result, models::GoogleUser};

#[derive(Clone)]
pub struct GoogleUserRepository {
    collection_name: String,
    db: FirestoreDb,
}

impl GoogleUserRepository {
    pub fn new(
        db: FirestoreDb,
        collection_name: impl AsRef<str>,
    ) -> Result<GoogleUserRepository> {
        Ok(GoogleUserRepository {
            collection_name: collection_name.as_ref().to_string(),
            db,
        })
    }

    pub async fn get<ID: AsRef<str>>(
        &self,
        id: ID,
    ) -> Result<Option<GoogleUser>> {
        let user: Option<GoogleUser> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.collection_name)
            .obj()
            .one(id.as_ref())
            .await
            .map_err(crate::Error::Firestore)?;

        Ok(user)
    }

    pub async fn update(&self, user: &GoogleUser) -> Result<()> {
        let _firestore_result: Result<GoogleUser> = self
            .db
            .fluent()
            .update()
            .in_col(&self.collection_name)
            .document_id(&user.id)
            .object(user)
            .execute()
            .await
            .map_err(crate::Error::Firestore);

        Ok(())
    }
}
