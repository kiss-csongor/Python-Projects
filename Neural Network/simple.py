import torch
import torch.nn as nn
import torch.nn.functional as F
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split

# Model osztály készítés, ami örökli az nn.Module-t
class Model(nn.Module):
    def __init__(self, in_features=4, h1=8, h2=9, output_features=3):
        super().__init__()
        self.fc1 = nn.Linear(in_features, h1)
        self.fc2 = nn.Linear(h1, h2)
        self.fc3 = nn.Linear(h2, output_features)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x) 
        return x

torch.manual_seed(41)
model = Model()

url = 'https://gist.githubusercontent.com/curran/a08a1080b88344b0c8a7/raw/0e7a9b0a5d22642a06d3d5b9bcbad9890c8ee534/iris.csv'
dataframe = pd.read_csv(url)

# Címkék numerikus átalakítása
dataframe['species'] = dataframe['species'].replace('setosa', 0)
dataframe['species'] = dataframe['species'].replace('versicolor', 1)
dataframe['species'] = dataframe['species'].replace('virginica', 2)

x = dataframe.drop('species', axis=1)
y = dataframe['species']

x = x.values
y = y.values

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=67)

# Tensor típusúvá alakítás
x_train = torch.FloatTensor(x_train)
x_test = torch.FloatTensor(x_test)
y_train = torch.LongTensor(y_train)  # Javítva FloatTensor-ról LongTensor-ra
y_test = torch.LongTensor(y_test)

criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

epochs = 100
losses = []

for i in range(epochs):
    y_pred = model.forward(x_train)

    loss = criterion(y_pred, y_train)  # Javítva y_pred helyett y_train használata
    losses.append(loss.detach().numpy())

    if i % 10 == 0:
        print(f'Epoch: {i} and loss: {loss.item()}')

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

plt.plot(range(epochs), losses)
plt.ylabel("loss/error")
plt.xlabel("epoch")