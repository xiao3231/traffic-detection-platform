/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IHeadline = {}

export default function Headline(props: IHeadline) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
