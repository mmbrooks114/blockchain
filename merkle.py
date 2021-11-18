# -*- coding: utf-8 -*-
"""
Created on Thu Sep 16 14:07:53 2021

@author: malfr
"""
import hashlib as Hash
import csv

#class for merkle tree data structure
class MerkleTree:
    
    #constructor for MerkleTree object; takes a list of tranactions and creates the repspective merkle tree that
    #represents that list of transaction.
    def __init__(self, leaves = None):
        #if there is a list passsed into the constructor, they are hashed into the transaction id's the merkle tree
        #is built. The root of the tree points to the node containing the merkle root of the tree. Otherwise, the
        #tree is created with a root that points to None
        if(leaves):
            i = 0
            for leaf in leaves:
                leaves[i] = MerkleTree.Node(Hash.sha256(leaf.encode()).hexdigest())
                i += 1
            self.root = self.buildMerkle(leaves)
        else:
            self.root = None
    
    #override of string method for the MerkleTree class. returns the root of the tree.
    def __str__(self):
        return str(self.root)
    
    #string that represents specific instance of a MerkleTree; used for error reading
    def __repr(self):
        return ("Merkle Tree", str(self.root))
            
    #method used to recursively construct a merkle tree from a list of nodes
    def buildMerkle(self, List):
        #returns the node containing the merkle root once there is only one node in the list.
        if(len(List) == 1):
            return List[0]
        
        else:
            #if there is an odd number of items in the list, it copies and appends the last node of the list to
            #itself. The children of the copy are set to '#' to denote that this process to prevent duplication
            #of referenced data.
            if(len(List) % 2 != 0):
                List.append(self.Node(str(List[len(List)-1]), self.Node("#"), self.Node("#")))
            i = 0
            newNodes = []
            #appends new nodes that are calculated by hashing the concatenation of each pair of transaction id's
            #to NewNodes and recalls the method on newNodes
            for nodes in List:
                if(i % 2 == 0):
                    newNodes.append(self.Node(Hash.sha256((str(List[i]) + str(List[i+1])).encode()).hexdigest(), List[i], List[i+1]))
                i += 1
            return self.buildMerkle(newNodes)
    
    #method used to print transaction id's (leaf nodes) for a given merkle tree. Method is passed the root of the tree as a
    #parameter and the id's are printed in order of left to right.
    def printtree(self, node):
        if(node.info == '#'):
            return
        elif(node.left == None and node.right == None):
            print(node.info)
        else: 
            self.printtree(node.left)
            self.printtree(node.right)

    #method that returns a list containing the transaction id's of the merkle tree in order from left to right
    def treetolist(self, node, List = []):
        if(node.info == '#'):
            return
        if(node.left == None and node.right == None):
            List.append(node.info)
        else: 
            self.treetolist(node.left)
            self.treetolist(node.right)
            return List
    
    #implementation of the treetolist() method
    def treeToList(self):
        return self.treetolist(self.root)
    
    #implementation of the printtree() method
    def printTree(self):
        self.printtree(self.root)
    
    #method to save merkle tree data. data is saved as a list of transaction id's with the root of the respective
    #merkle tree appended to the end of the transaction id's. If the given file storing the data exists, this method
    #will check all stored data in the file and append the new tree data to the end if no records of the data
    #exist already
    def saveTree(self, fileName):
        if(self.root == None):
            raise ValueError("Tree is empty")
        
        List = self.treeToList()
        List.append(self.root.info)
        
        try:
            with open(fileName, "x") as fout:
                csvWriter = csv.writer(fout)
                csvWriter.writerow(List)
                return True
        except FileExistsError:
            with open(fileName, "r") as fout:
                csvReader = csv.reader(fout)
                for row in csvReader:
                    if(row == List):
                        raise ValueError("Transaction is already recorded")
            with open(fileName, "a") as fout:
                csvWriter = csv.writer(fout)
                csvWriter.writerow(List)
                return True
    
    #method to load an instance of a merkle tree from a file containing merkle tree data; Searches for give merkle
    #root and generates tree from data associated to that merkle root (if it exists within the file)
    def loadTree(self, fileName, merkleRoot):
        try:
            with open(fileName,"r") as fout:
                csvReader = csv.reader(fout)
                for row in csvReader:
                    if(row[-1] == merkleRoot):
                        List = self.listToNodes(row[:-1])
                        self.root = self.buildMerkle(List)
                        return True
                    raise ValueError("Tree with Merkle Root '{}' not found in directory.".format(merkleRoot))
                            
                    
        except FileNotFoundError:
            raise ValueError("File '{}' not found in directory.".format(fileName))
    
    #method to take list of transaction id's and return a list of nodes containing the id's.
    def listToNodes(self, List):
        nodes = []
        for l in List:
            nodes.append(MerkleTree.Node(l))
        return nodes
    
    #Node class that is used to build merkle tree structure; each node holds a piece of information and points
    #to at most two children (one left and one right).
    class Node:
        def __init__(self, info = None, left = None, right = None):
            self.info = info
            self.left = left
            self.right = right
        
        #string representing a node instance in the error report
        def __repr__(self):
            return ("Node",self.info)
        
        #override of string method for node class; returns the info held within the node
        def __str__(self):
            return self.info
#################################################################################################################

