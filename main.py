import concurrent.futures
import multiprocessing
import pandas as pd
import numpy as np
import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GridSearchCV
from sklearn.preprocessing import LabelEncoder
import pickle
import tldextract
import helpers as h

if __name__ == '__main__':
    pd.set_option('display.max_columns', None)

    num_processes = multiprocessing.cpu_count() * 10
    print("Threading will be conducted with " + num_processes.__str__() + " tasks.")
    whoisQueryCounter = 0
    is_new_file = False

    processed_data = pd.DataFrame()

    try:
        processed_data = pd.read_csv('processed.csv')
    except FileNotFoundError:
        print('Could not find processed.csv file. Creating a new one.')
        is_new_file = True

    initial_data = pd.read_csv('malicious_phish.csv')
    data = initial_data[(processed_data.shape[0]):].reset_index()

    domainEncoder = LabelEncoder()

    strLengthsData = data['url'].str.len()
    isHttps = data['url'].str.contains("https://*")
    isWWW = data['url'].str.contains("www")
    containsNumbers = data['url'].apply(lambda element: tldextract.extract(element).domain.count("[1-9]"))

    domainExtension = data['url'].apply(lambda element: tldextract.extract(element).suffix)
    domainExtension = domainEncoder.fit_transform(domainExtension)

    print("Started whois queries...")
    with concurrent.futures.ThreadPoolExecutor(num_processes) as executor:
        whoisData = list(tqdm.tqdm(executor.map(h.get_whois_data, data['url']), total=len(data), unit='url', smoothing=0))
    print("Finished!")

    whoisCreationDate = pd.Series(list(map(h.get_creation_time, whoisData)))
    whoisExpirationDate = pd.Series(list(map(h.get_expiration_date, whoisData)))

    whoisCountry = pd.Series(list(map(h.get_expiration_date, whoisData)))
    whoisCountry = domainEncoder.fit_transform(whoisCountry)

    whoisRegistrar = pd.Series(list(map(h.get_registrar, whoisData)))

    x = pd.DataFrame()
    x['length'] = strLengthsData
    x['isHttps'] = isHttps
    x['isWWW'] = isWWW
    x['numbers'] = containsNumbers
    x['extension'] = domainExtension
    x['creation'] = whoisCreationDate
    x['expiration'] = whoisExpirationDate
    x['country'] = whoisCountry
    x['registrar'] = whoisRegistrar

    if not is_new_file:
        x = pd.concat([processed_data, x])

    x.to_csv('processed.csv', index=False)

    y = initial_data.head(x.shape[0])['type']

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.20, random_state=101)

    print(f'X_train : {x_train.shape}')
    print(f'y_train : {y_train.shape}')
    print(f'X_test : {x_test.shape}')
    print(f'y_test : {y_test.shape}')

    # Number of trees in random forest
    n_estimators = [int(x) for x in np.linspace(start=20, stop=160, num=10)]
    # Number of features to consider at every split
    max_features = ['sqrt']
    # Maximum number of levels in tree
    max_depth = [2, 4, 6, 8]
    # Minimum number of samples required to split a node
    min_samples_split = [2, 5]
    # Minimum number of samples required at each leaf node
    min_samples_leaf = [1, 2]
    # Method of selecting samples for training each tree
    bootstrap = [True, False]

    param_grid = {'n_estimators': n_estimators,
                  'max_features': max_features,
                  'max_depth': max_depth,
                  'min_samples_split': min_samples_split,
                  'min_samples_leaf': min_samples_leaf,
                  'bootstrap': bootstrap}
    print(param_grid)

    rf_Model = RandomForestClassifier()

    rf_Grid = GridSearchCV(estimator=rf_Model, param_grid=param_grid, cv=3, verbose=2, n_jobs=4)

    rf_Grid.fit(x_train, y_train)

    print(rf_Grid.best_params_)

    print(f'Train Accuracy - : {rf_Grid.score(x_train, y_train):.3f}')
    print(f'Test Accuracy - : {rf_Grid.score(x_test, y_test):.3f}')

    with open("model.pkl", "wb") as file:
        pickle.dump(rf_Grid, file)
