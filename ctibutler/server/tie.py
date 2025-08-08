import numpy as np
from enum import Enum
from rest_framework.exceptions import ValidationError

"""
More implementation details at https://github.com/center-for-threat-informed-defense/technique-inference-engine/blob/main/src/tie/recommender/wals_recommender.py
"""

class PredictionMethod(Enum):
    """A method for predicting values in the data matrix."""

    DOT = "dot"
    COSINE = "cosine"

class ExtractedWalsRecommender():
    def load(self, path):
        loaded = np.load(path)
        self._U: np.ndarray = loaded['U']
        self._V: np.ndarray = loaded['V']
        self.all_techniques = loaded['technique_ids']
        c, epoch, rc = loaded['hyperparameters'][0]
        self.hyperparameters = dict(c=c, epoch=epoch, regularization_coefficient=rc)
        self.n = self._V.shape[0]
        self.k = self._U.shape[1]

    def make_predictions(self, techniques):
        technique_ids_to_indices = {
            self.all_techniques[i]: i for i in range(len(self.all_techniques))
        }

                
        if missing := set(techniques).difference(technique_ids_to_indices):
            raise ValidationError(
                    dict(error=f"Model has not been trained on {len(missing)} passed techniques.", unknown_techniques=list(missing))
                )
        
        technique_indices = set()
        for technique in techniques:
            if technique in technique_ids_to_indices:
                technique_indices.add(technique_ids_to_indices[technique])
        technique_indices = list(technique_indices)
        entries = np.zeros((self.n,))
        entries[technique_indices] = 1
        
        predictions = self.predict_new_entity(
            entries, method=PredictionMethod.DOT, **self.hyperparameters
        )
        return sorted(list(zip(self.all_techniques, predictions)), key=lambda x: x[1], reverse=True)[:20]
    
    def predict_new_entity(
        self,
        entity: np.ndarray,
        c: float,
        regularization_coefficient: float,
        method: PredictionMethod = PredictionMethod.DOT,
        **kwargs,
    ) -> np.array:
        """Recommends items to an unseen entity.

        Args:
            entity: A length-n sparse tensor of consisting of the new entity's
                ratings for each item, indexed exactly as the items used to
                train this model.
            c: Weight for negative training examples in the loss function,
                ie each positive example takes weight 1, while negative examples take
                discounted weight c.  Requires 0 < c < 1.
            regularization_coefficient: Coefficient on the embedding regularization
                term.
            method: The prediction method to use.

        Returns:
            An array of predicted values for the new entity.
        """
        assert entity.shape == (self.n,)

        alpha = (1 / c) - 1

        new_entity_factor = self._update_factor(
            opposing_factors=self._V,
            data=np.expand_dims(entity, axis=1),
            alpha=alpha,
            regularization_coefficient=regularization_coefficient,
        )

        assert new_entity_factor.shape == (1, self._U.shape[1])

        return np.squeeze(
            calculate_predicted_matrix(new_entity_factor, self._V, method)
        )
    
    def _update_factor(
        self,
        opposing_factors: np.ndarray,
        data: np.ndarray,
        alpha: float,
        regularization_coefficient: float,
    ) -> np.ndarray:
        """Updates factors according to least squares on the opposing factors.

        Determines factors which minimize loss on data based on opposing_factors.
        For example, if opposing_factors are the item factors, determines the entity
        factors which minimize loss on data.

        Args:
            opposing_factors: a pxk array of the fixed factors in the optimization step
                (ie entity or item factors).  Requires p, k > 0.
            predictions: A pxq array of the observed values for each of the
                entities/items associated with the p opposing_factors and the q
                items/entities associated with factors. Requires p, q > 0.
            alpha: Weight for positive training examples such that each positive example
                takes value alpha + 1.  Requires alpha > 0.
            regularization_coefficient: coefficient on the embedding regularization
                term. Requires regularization_coefficient > 0.

        Returns:
            A qxk array of recomputed factors which minimize error.
        """
        # assert preconditions
        p, k = opposing_factors.shape
        q = data.shape[1]
        assert p > 0
        assert k == self.k
        assert p == data.shape[0]
        assert q > 0
        assert alpha > 0
        assert regularization_coefficient >= 0

        def V_T_C_I_V(V, c_array):
            _, k = V.shape

            c_minus_i = c_array - 1
            nonzero_c = tuple(np.nonzero(c_minus_i)[0].tolist())

            product = np.zeros((k, k))

            for i in nonzero_c:
                v_i = np.expand_dims(V[i, :], axis=1)

                square_addition = v_i @ v_i.T
                assert square_addition.shape == (k, k)

                product += square_addition

            return product

        # in line with the paper,
        # we will use variable names as if we are updating user factors based
        # on V, the item factors.  Since the process is the same for both,
        # the variable names are interchangeable.  This just makes following
        # along with the paper easier.
        V = opposing_factors

        new_U = np.ndarray((q, k))
        # for each item embedding

        V_T_V = V.T @ V
        # update each of the q user factors
        for i in range(q):
            P_u = data[:, i]
            # C is c if unobserved, one otherwise
            C_u = np.where(P_u > 0, alpha + 1, 1)
            assert C_u.shape == (p,)

            confidence_scaled_v_transpose_v = V_T_C_I_V(V, C_u)

            # X = (V^T CV + \lambda I)^{-1} V^T CP
            inv = np.linalg.inv(
                V_T_V
                + confidence_scaled_v_transpose_v
                + regularization_coefficient * np.identity(k)
            )

            # removed C_u here since unneccessary in binary case
            # P_u is already binary
            U_i = inv @ V.T @ P_u

            new_U[i, :] = U_i

        return new_U

def calculate_predicted_matrix(
    U: np.ndarray, V: np.ndarray, method: PredictionMethod = PredictionMethod.DOT
) -> np.ndarray:
    """Calculates the prediction matrix UV^T according to the dot or cosine product.

    Args:
        U: mxk array of entity embeddings
        V: nxk array of item embeddings
        method: Matrix product method to use.

    Returns:
        The matrix product UV^T, according to method.
    """
    if method == PredictionMethod.DOT:
        U_scaled = U
        V_scaled = V
    elif method == PredictionMethod.COSINE:
        U_norm = np.expand_dims(np.linalg.norm(U, ord=2, axis=1), axis=1)
        V_norm = np.expand_dims(np.linalg.norm(V, ord=2, axis=1), axis=1)

        # if norm is 0, ie if the embedding is 0
        # then do not scale by norm at all
        U_norm[U_norm == 0.0] = 1.0
        V_norm[V_norm == 0.0] = 1.0

        assert U_norm.shape == (U.shape[0], 1)
        assert V_norm.shape == (V.shape[0], 1)

        assert not np.isnan(U_norm).any()
        assert not np.isnan(V_norm).any()

        U_scaled = np.divide(U, U_norm)
        V_scaled = np.divide(V, V_norm)

    return U_scaled @ V_scaled.T
