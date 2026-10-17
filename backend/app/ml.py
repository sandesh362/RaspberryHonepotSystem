import hashlib
import json
import threading
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from .detection import FEATURE_NAMES

LABELS=['control','scan','auth_guessing','shell_activity','http_probe']

class Intelligence:
    """An explicitly synthetic, reproducible feasibility benchmark. No pickle loading."""
    def __init__(self,data_dir):
        self.path=data_dir/'model-evaluation.json'
        self.lock=threading.Lock(); self.model=None; self.anomaly=None
        self.report={'status':'unavailable','scope':'Synthetic lab features only; not field validated.'}

    def train(self):
        with self.lock:
            rng=np.random.default_rng(20261017)
            X=[]; y=[]; groups=[]
            for label in LABELS:
                for run in range(80):
                    duration=float(rng.uniform(2,58))
                    if label=='control': row=[rng.integers(1,7),1,rng.integers(0,3),0,rng.integers(0,6),rng.integers(0,3),duration]
                    elif label=='scan':
                        n=int(rng.integers(8,45)); row=[n,n,0,0,0,0,rng.uniform(1,12)]
                    elif label=='auth_guessing':
                        n=int(rng.integers(4,20)); row=[n+1,1,n,0,0,0,duration]
                    elif label=='shell_activity':
                        n=int(rng.integers(1,12)); row=[n+3,1,rng.integers(0,3),n,0,0,duration]
                    else:
                        n=int(rng.integers(7,30)); row=[n,1,0,0,n,int(rng.integers(3,12)),duration]
                    # Deliberate overlap; the metric describes this generator, not deployed accuracy.
                    X.append(row); y.append(label); groups.append(f'{label}-independent-run-{run}')
            X=np.asarray(X,dtype=float); y=np.asarray(y)
            train,test=next(GroupShuffleSplit(n_splits=1,test_size=.25,random_state=73).split(X,y,groups))
            model=RandomForestClassifier(n_estimators=80,max_depth=7,min_samples_leaf=2,random_state=73,n_jobs=1)
            model.fit(X[train],y[train])
            anomaly=IsolationForest(n_estimators=60,random_state=73,contamination=.08,n_jobs=1).fit(X[train][y[train]=='control'])
            self.model,self.anomaly=model,anomaly
            predicted=model.predict(X[test]); result=classification_report(y[test],predicted,labels=LABELS,output_dict=True,zero_division=0)
            self.report={'status':'lab-trained','model_id':'rf-lab-v1','trained_at':datetime.now(timezone.utc).isoformat(),'scope':'Synthetic feature benchmark; not real network accuracy or a field validation.','dataset_source':'Seeded synthetic feature generator, 80 independent runs per behavior','feature_names':FEATURE_NAMES,'feature_schema_sha256':hashlib.sha256(json.dumps(FEATURE_NAMES).encode()).hexdigest(),'dataset_sha256':hashlib.sha256(X.tobytes()+y.tobytes()).hexdigest(),'seed':73,'generator_seed':20261017,'samples':len(X),'train_runs':len(train),'test_runs':len(test),'split':'GroupShuffleSplit: whole synthetic runs, 75% training / 25% holdout','macro_f1':result['macro avg']['f1-score'],'per_label':[{ 'label':label,**result[label]} for label in LABELS],'labels':LABELS,'confusion_matrix':confusion_matrix(y[test],predicted,labels=LABELS).tolist(),'feature_importance':dict(zip(FEATURE_NAMES,self.model.feature_importances_.tolist())),'limitations':['Synthetic features do not establish real-world generalization.','Primary label only; rule findings remain multi-behavior.','Real capture dataset, day-separated validation and hybrid ablation are Phase 2.','Scores below 0.60 are shown as uncertain; threshold is not field calibrated.']}
            self.path.write_text(json.dumps(self.report,indent=2),encoding='utf-8')
            return self.report

    def predict(self,values):
        if self.model is None: return {'status':'unavailable'}
        probabilities=self.model.predict_proba([values])[0]
        index=int(np.argmax(probabilities)); confidence=float(probabilities[index])
        return {'status':'provisional','label':str(self.model.classes_[index]) if confidence>=.6 else 'uncertain','confidence':round(confidence,4),'novelty_score':round(float(-self.anomaly.score_samples([values])[0]),4),'model_id':'rf-lab-v1','scope':'Synthetic lab model; primary behavior estimate, not maliciousness probability.','features':dict(zip(FEATURE_NAMES,values))}
